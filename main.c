/*
 * Copyright (c) 2024 Kirill A. Korinsky <kirill@korins.ky>
 * Copyright (c) 2019 Martijn van Duren <martijn@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/sha.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <libgen.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include "openbsd-compat.h"
#include "opensmtpd.h"
#include "mheader.h"

#define nitems(_a) (sizeof((_a)) / sizeof((_a)[0]))

/* RFC 8617 Section 3.9 */
enum ar_chain_status {
	AR_UNKNOWN,
	AR_NONE,
	AR_PASS,
	AR_FAIL
};

struct signature {
	char *signature;
	size_t size;
	size_t len;
};

struct message {
	FILE *origf;
	int arc_i;
	char *arc_ar;
	enum ar_chain_status arc_cv;
	int parsing_headers;
	char **headers;
	int lastheader;
	size_t body_whitelines;
	int has_body;
	struct signature signature;
	EVP_MD_CTX *dctx;
};

/* RFC 6376 section 5.4.1 */
static char *dkim_headers[] = {
	"From",
	"Reply-To",
	"Subject",
	"Date",
	"To",
	"Cc",
	"Resent-Date",
	"Resent-From",
	"Resent-To",
	"Resent-Cc",
	"In-Reply-To",
	"References",
	"List-Id",
	"List-Help",
	"List-Unsubscribe",
	"List-Subscribe",
	"List-Post",
	"List-Owner",
	"List-rchive"
};

/* RFC 6376 section 5.4.1 + RFC8617 Section 4.1.2 */
static char *arc_sign_headers[] = {
	"From",
	"Reply-To",
	"Subject",
	"Date",
	"To",
	"Cc",
	"Resent-Date",
	"Resent-From",
	"Resent-To",
	"Resent-Cc",
	"In-Reply-To",
	"References",
	"List-Id",
	"List-Help",
	"List-Unsubscribe",
	"List-Subscribe",
	"List-Post",
	"List-Owner",
	"List-rchive",
	"DKIM-Signature"
};

/* RFC8617 Section 5.1.1 */
static char *arc_seal_headers[] = {
	"ARC-Authentication-Results",
	"ARC-Message-Signature",
	"ARC-Seal"
};

static char **sign_headers = dkim_headers;
static size_t nsign_headers = nitems(dkim_headers);

static char *hashalg = "sha256";
static char *cryptalg = "rsa";

#define CANON_SIMPLE 0
#define CANON_RELAXED 1
static int canonheader = CANON_SIMPLE;
static int canonbody = CANON_SIMPLE;

static int addtime = 0;
static long long addexpire = 0;
static int addheaders = 0;

static char **domain = NULL;
static size_t ndomains = 0;
static char *selector = NULL;

static EVP_PKEY *pkey;
static const EVP_MD *hash_md;
static int keyid = EVP_PKEY_RSA;
static int sephash = 0;

#define SIGNATURE_LINELEN 78

/* RFC 8617 Section 4.2.1 */
#define ARC_MIN_I 1
#define ARC_MAX_I 50

enum mode {
	DKIMSIGN,
	ARCSIGN,
	ARCSEAL
} mode = DKIMSIGN;

void usage(void);
void sign_adddomain(char *);
void sign_headers_set(char *);
int sign_dataline(struct osmtpd_ctx *, const char *);
void *message_new(struct osmtpd_ctx *);
void message_free(struct osmtpd_ctx *, void *);
void sign_parse_header(struct message *, char *, int);
void sign_parse_body(struct message *, char *);
const char *ar_chain_status2str(enum ar_chain_status);
void sign_sign(struct osmtpd_ctx *);
void signature_printheader(struct message *, const char *);
void signature_printf(struct message *, char *, ...)
	__attribute__((__format__ (printf, 2, 3)));
void signature_normalize(struct message *);
const char *sign_domain_select(struct message *, char *);
void signature_need(struct message *, size_t);
int sign_sign_init(struct message *);

int
main(int argc, char *argv[])
{
	int ch;
	FILE *file;
	char *line;
	size_t linesz;
	ssize_t linelen;
	char argv0[PATH_MAX];
	char *name;
	const char *errstr;
	const char *dkimsignopstr = "a:c:D:d:h:k:s:tx:z";
	const char *arcsignoptstr = "a:c:D:d:h:k:s:tx:";
	const char *arcsealoptstr = "a:D:d:k:s:tx:z";
	const char *optstr = dkimsignopstr;

	strlcpy(argv0, argv[0], sizeof(argv0));
	name = basename(argv0);
	if (strcmp(name, "filter-arcsign") == 0) {
		mode = ARCSIGN;
		optstr = arcsignoptstr;
		sign_headers = arc_sign_headers;
		nsign_headers = nitems(arc_sign_headers);
	} else if (strcmp(name, "filter-arcseal") == 0) {
		mode = ARCSEAL;
		canonheader = CANON_RELAXED;
		sign_headers = arc_seal_headers;
		nsign_headers = nitems(arc_seal_headers);
		optstr = arcsealoptstr;
	} else if (strcmp(name, "filter-dkimsign") != 0)
		usage();

	while ((ch = getopt(argc, argv, optstr)) != -1) {
		switch (ch) {
		case 'a':
			if (strncmp(optarg, "rsa-", 4) == 0) {
				cryptalg = "rsa";
				hashalg = optarg + 4;
				keyid = EVP_PKEY_RSA;
				sephash = 0;
			} else if (strncmp(optarg, "ed25519-", 8) == 0) {
				hashalg = optarg + 8;
				cryptalg = "ed25519";
				keyid = EVP_PKEY_ED25519;
				sephash = 1;
			} else
				osmtpd_errx(1, "invalid algorithm");
			break;
		case 'c':
			if (strncmp(optarg, "simple", 6) == 0) {
				canonheader = CANON_SIMPLE;
				optarg += 6;
			} else if (strncmp(optarg, "relaxed", 7) == 0) {
				canonheader = CANON_RELAXED;
				optarg += 7;
			} else
				osmtpd_errx(1, "Invalid canonicalization");
			if (optarg[0] == '/') {
				if (strcmp(optarg + 1, "simple") == 0)
					canonbody = CANON_SIMPLE;
				else if (strcmp(optarg + 1, "relaxed") == 0)
					canonbody = CANON_RELAXED;
				else
					osmtpd_errx(1,
					    "Invalid canonicalization");
			} else if (optarg[0] == '\0')
				canonbody = CANON_SIMPLE;
			else
				osmtpd_errx(1, "Invalid canonicalization");
			break;
		case 'D':
			if ((file = fopen(optarg, "r")) == NULL)
				osmtpd_err(1, "Can't open domain file (%s)",
				    optarg);
			do {
				line = NULL;
				linesz = 0;
				linelen = getline(&line, &linesz, file);
				if (linelen > 0) {
					if (line[linelen - 1] == '\n')
						line[linelen - 1] = '\0';
					if (line[0] == '#')
						continue;
					sign_adddomain(line);
				}
			} while (linelen != -1);
			if (ferror(file))
				osmtpd_err(1, "Error reading domain file (%s)",
				    optarg);
			fclose(file);
			break;
		case 'd':
			sign_adddomain(optarg);
			break;
		case 'h':
			sign_headers_set(optarg);
			break;
		case 'k':
			if ((file = fopen(optarg, "r")) == NULL)
				osmtpd_err(1, "Can't open key file (%s)",
				    optarg);
			pkey = PEM_read_PrivateKey(file, NULL, NULL, NULL);
			if (pkey == NULL)
				osmtpd_errx(1, "Can't read key file");
			fclose(file);
			break;
		case 's':
			selector = optarg;
			break;
		case 't':
			addtime = 1;
			break;
		case 'x':
			addexpire = strtonum(optarg, 1, INT64_MAX, &errstr);
			if (addexpire == 0)
				osmtpd_errx(1, "Expire offset is %s", errstr);
			break;
		case 'z':
			addheaders++;
			break;
		default:
			usage();
		}
	}

	OpenSSL_add_all_digests();

	if (pledge("tmppath stdio", NULL) == -1)
		osmtpd_err(1, "pledge");

	if ((hash_md = EVP_get_digestbyname(hashalg)) == NULL)
		osmtpd_errx(1, "Can't find hash: %s", hashalg);

	if (domain == NULL || selector == NULL || pkey == NULL)
		usage();

	if (EVP_PKEY_id(pkey) != keyid)
		osmtpd_errx(1, "Key is not of type %s", cryptalg);

	osmtpd_register_filter_dataline(sign_dataline);
	osmtpd_local_message(message_new, message_free);
	osmtpd_run();

	return 0;
}

void
sign_adddomain(char *d)
{
	domain = reallocarray(domain, ndomains + 1, sizeof(*domain));
	if (domain == NULL)
		osmtpd_err(1, "reallocarray");
	domain[ndomains++] = d;
}

int
sign_dataline(struct osmtpd_ctx *ctx, const char *line)
{
	struct message *message = ctx->local_message;
	char *linedup;
	size_t linelen;

	linelen = strlen(line);
	if (fprintf(message->origf, "%s\n", line) < (int) linelen) {
		osmtpd_warnx(ctx, "Couldn't write to tempfile");
		return -1;
	}

	if (line[0] == '.' && line[1] =='\0') {
		sign_sign(ctx);
	} else if (linelen !=  0 && message->parsing_headers) {
		if (line[0] == '.')
			line++;
		if ((linedup = strdup(line)) == NULL)
			osmtpd_err(1, "strdup");
		sign_parse_header(message, linedup, 0);
		free(linedup);
	} else if (linelen == 0 && message->parsing_headers) {
		if (mode == DKIMSIGN && addheaders > 0)
			signature_printf(message, "; ");
		message->parsing_headers = 0;
	} else if (mode == DKIMSIGN || mode == ARCSIGN) {
		if (line[0] == '.')
			line++;
		if ((linedup = strdup(line)) == NULL)
			osmtpd_err(1, "strdup");
		sign_parse_body(message, linedup);
		free(linedup);
	}

	return 0;
}

void *
message_new(struct osmtpd_ctx *ctx)
{
	struct message *message;

	if ((message = calloc(1, sizeof(*message))) == NULL) {
		osmtpd_warn(ctx, "calloc");
		return NULL;
	}

	if ((message->origf = tmpfile()) == NULL) {
		osmtpd_warn(ctx, "Failed to open tempfile");
		goto fail;
	}
	message->parsing_headers = 1;

	message->body_whitelines = 0;
	message->headers = calloc(1, sizeof(*(message->headers)));
	if (message->headers == NULL) {
		osmtpd_warn(ctx, "calloc");
		goto fail;
	}
	message->lastheader = 0;
	message->signature.signature = NULL;
	message->signature.size = 0;
	message->signature.len = 0;

	switch (mode) {
	case DKIMSIGN:
		signature_printf(message,
		    "DKIM-Signature: v=%s; a=%s-%s; c=%s/%s; s=%s; ", "1",
		    cryptalg, hashalg,
		    canonheader == CANON_SIMPLE ? "simple" : "relaxed",
		    canonbody == CANON_SIMPLE ? "simple" : "relaxed", selector);
		if (addheaders > 0)
			signature_printf(message, "z=");

		break;
	case ARCSIGN:
		signature_printf(message, "ARC-Message-Signature: ");
		break;
	case ARCSEAL:
		signature_printf(message, "ARC-Seal: ");
	}

	if ((message->dctx = EVP_MD_CTX_new()) == NULL) {
		osmtpd_warnx(ctx, "EVP_MD_CTX_new");
		goto fail;
	}
	if (EVP_DigestInit_ex(message->dctx, hash_md, NULL) <= 0) {
		osmtpd_warnx(ctx, "EVP_DigestInit_ex");
		goto fail;
	}

	return message;
fail:
 	message_free(ctx, message);
 	return NULL;
}

void
message_free(struct osmtpd_ctx *ctx, void *data)
{
	struct message *message = data;
	size_t i;

	fclose(message->origf);
	EVP_MD_CTX_free(message->dctx);
	free(message->signature.signature);
	for (i = 0; message->headers != NULL &&
	    message->headers[i] != NULL; i++)
		free(message->headers[i]);
	free(message->headers);
	free(message);
}

void
sign_headers_set(char *headers)
{
	size_t i;
	int has_from = 0;

	nsign_headers = 1;

	for (i = 0; headers[i] != '\0'; i++) {
		/* RFC 5322 field-name */
		if (!(headers[i] >= 33 && headers[i] <= 126))
			osmtpd_errx(1, "-h: invalid character");
		if (headers[i] == ':') {
			/* Test for empty headers */
			if (i == 0 || headers[i - 1] == ':')
				osmtpd_errx(1, "-h: header can't be empty");
			nsign_headers++;
		}
		headers[i] = tolower(headers[i]);
	}
	if (headers[i - 1] == ':')
		osmtpd_errx(1, "-h: header can't be empty");

	if ((sign_headers = reallocarray(NULL, nsign_headers + 1,
	    sizeof(*sign_headers))) == NULL)
		osmtpd_errx(1, "reallocarray");

	for (i = 0; i < nsign_headers; i++) {
		sign_headers[i] = headers;
		if (i != nsign_headers - 1) {
			headers = strchr(headers, ':');
			headers++[0] = '\0';
		}
		if (strcasecmp(sign_headers[i], "from") == 0)
			has_from = 1;
	}
	if (!has_from)
		osmtpd_errx(1, "From header must be included");
}

void
sign_parse_header(struct message *message, char *line, int force)
{
	long li;
	size_t i;
	size_t r, w;
	size_t linelen;
	size_t lastheader;
	size_t hlen;
	int fieldname = 0;
	char **mtmp;
	char *htmp;
	char *tmp;

	if (mode == DKIMSIGN && addheaders == 2 && !force)
	    signature_printheader(message, line);

	if ((line[0] == ' ' || line[0] == '\t')) {
		/* concat ARC-AR header */
		if (message->arc_i == -1) {
			linelen = 1;
			linelen += strlen(line);
			linelen += strlen(message->arc_ar);
			htmp = reallocarray(message->arc_ar, linelen, sizeof(*htmp));
			if (htmp == NULL) {
				osmtpd_err(1, "malloc");
				return;
			}
			message->arc_ar = htmp;
			if (strlcat(htmp, line, linelen) >= linelen) {
				osmtpd_errx(1, "malloc");
				return;
			}
		}
		if (!message->lastheader)
			return;
	}
	if ((line[0] != ' ' && line[0] != '\t')) {
		message->lastheader = 0;
		/* The next header, parse captured ARC-AR */
		if (message->arc_i == -1) {
			message->arc_i = -2;
			hlen = 0;
			if (message->arc_ar[hlen] != 'i')
				goto skpi_arc_ar;
			hlen++;
			while (message->arc_ar[hlen] == ' ' ||
			    message->arc_ar[hlen] == '\t')
				hlen++;
			if (message->arc_ar[hlen] != '=')
				goto skpi_arc_ar;
			hlen++;
			li = strtol(message->arc_ar + hlen, &htmp, 10);
			if (li < ARC_MIN_I || li > ARC_MAX_I)
				goto skpi_arc_ar;
			message->arc_i = li;
			hlen = htmp - message->arc_ar;
			while (message->arc_ar[hlen] != '\0') {
				while (message->arc_ar[hlen] != '\0' &&
				    message->arc_ar[hlen] != ' ' &&
				    message->arc_ar[hlen] != '\t') {
					/* skip quoted strings */
					if (message->arc_ar[hlen] == '"')
						while (message->arc_ar[hlen] != '\0' &&
						    message->arc_ar[hlen] != '"')
							hlen++;
					hlen++;
				}
				while (message->arc_ar[hlen] == ' ' ||
				    message->arc_ar[hlen] == '\t')
					hlen++;
				if (message->arc_ar[hlen] == '\0')
					break;
				if (strncasecmp("arc", message->arc_ar + hlen, 3) != 0) {
					hlen++;
					continue;
				}
				hlen += 3;
				while (message->arc_ar[hlen] == ' ' ||
				    message->arc_ar[hlen] == '\t')
					hlen++;
				if (message->arc_ar[hlen] != '=')
					continue;
				hlen++;
				while (message->arc_ar[hlen] == ' ' ||
				    message->arc_ar[hlen] == '\t')
					hlen++;
				if (message->arc_i == ARC_MIN_I &&
				    !strncasecmp("none", message->arc_ar + hlen, 4)) {
					hlen += 4;
					message->arc_cv = AR_NONE;
				}
				else if (!strncasecmp("pass", message->arc_ar + hlen, 4)) {
					hlen += 4;
					message->arc_cv = AR_PASS;
				} else
					message->arc_cv = AR_FAIL;
				if (message->arc_ar[hlen] != '\0' &&
				    message->arc_ar[hlen] != ' ' &&
				    message->arc_ar[hlen] != '\t' &&
				    message->arc_ar[hlen] != ';')
					message->arc_cv = AR_FAIL;
				break;
			}
		}
skpi_arc_ar:
		/* Capture the first ARC-AR header */
		hlen = sizeof("ARC-Authentication-Results:") - 1;
		if ((mode == ARCSIGN || mode == ARCSEAL) &&
		    message->arc_ar == NULL &&
		    strncasecmp("ARC-Authentication-Results:",
		    line, hlen) == 0) {
			while (line[hlen] == ' ' || line[hlen] == '\t')
				hlen++;
			message->arc_i = -1;
			if ((message->arc_ar = strdup(line + hlen)) == NULL) {
				osmtpd_err(1, "malloc");
				return;
			}
		}
		for (i = 0; i < nsign_headers; i++) {
			hlen = strlen(sign_headers[i]);
			if  (strncasecmp(line, sign_headers[i], hlen) == 0) {
				while (line[hlen] == ' ' || line[hlen] == '\t')
					hlen++;
				if (line[hlen] != ':')
					continue;
				break;
			}
		}
		if (i == nsign_headers && !force)
			return;
	}

	if (mode == DKIMSIGN && addheaders == 1 && !force)
	    signature_printheader(message, line);

	if (canonheader == CANON_RELAXED) {
		if (!message->lastheader)
			fieldname = 1;
		for (r = w = 0; line[r] != '\0'; r++) {
			if (line[r] == ':' && fieldname) {
				if (w > 0 && line[w - 1] == ' ')
					line[w - 1] = ':';
				else
					line[w++] = ':';
				fieldname = 0;
				while (line[r + 1] == ' ' ||
				    line[r + 1] == '\t')
					r++;
				continue;
			}
			if (line[r] == ' ' || line[r] == '\t' ||
			    line[r] == '\r' || line[r] == '\n') {
				if (r != 0 && w != 0 && line[w - 1] == ' ')
					continue;
				else
					line[w++] = ' ';
			} else if (fieldname) {
				line[w++] = tolower(line[r]);
				continue;
			} else
				line[w++] = line[r];
		}
		linelen = (w != 0 && line[w - 1] == ' ') ? w - 1 : w;
		line[linelen] = '\0';
	} else
		linelen = strlen(line);

	for (lastheader = 0; message->headers[lastheader] != NULL; lastheader++)
		continue;
	if (!message->lastheader) {
		mtmp = recallocarray(message->headers, lastheader + 1,
		    lastheader + 2, sizeof(*mtmp));
		if (mtmp == NULL)
			osmtpd_err(1, "reallocarray");
		message->headers = mtmp;

		if ((message->headers[lastheader] = strdup(line)) == NULL)
			osmtpd_err(1, "strdup");
		message->headers[lastheader + 1 ] = NULL;
		message->lastheader = 1;
	} else {
		lastheader--;
		linelen += strlen(message->headers[lastheader]);
		if (canonheader == CANON_SIMPLE)
			linelen += 2;
		linelen++;
		htmp = reallocarray(message->headers[lastheader], linelen,
		    sizeof(*htmp));
		if (htmp == NULL)
			osmtpd_err(1, "reallocarray");
		message->headers[lastheader] = htmp;
		if (canonheader == CANON_SIMPLE) {
			(void)strlcat(htmp, "\r\n", linelen);
		} else if (canonheader == CANON_RELAXED &&
		    (tmp = strchr(message->headers[lastheader], ':')) != NULL &&
		    tmp[1] == '\0')
			line++;

		(void)strlcat(htmp, line, linelen);
	}
}

void
sign_parse_body(struct message *message, char *line)
{
	size_t r, w;
	size_t linelen;

	if (canonbody == CANON_RELAXED) {
		for (r = w = 0; line[r] != '\0'; r++) {
			if (line[r] == ' ' || line[r] == '\t') {
				if (r != 0 && line[w - 1] == ' ')
					continue;
				else
					line[w++] = ' ';
			} else
				line[w++] = line[r];
		}
		linelen = (w != 0 && line[w - 1] == ' ') ? w - 1 : w;
		line[linelen] = '\0';
	} else
		linelen = strlen(line);

	if (line[0] == '\0') {
		message->body_whitelines++;
		return;
	}

	while (message->body_whitelines--) {
		if (EVP_DigestUpdate(message->dctx, "\r\n", 2) == 0)
			osmtpd_errx(1, "EVP_DigestUpdate");
	}
	message->body_whitelines = 0;
	message->has_body = 1;

	if (EVP_DigestUpdate(message->dctx, line, linelen) == 0 ||
	    EVP_DigestUpdate(message->dctx, "\r\n", 2) == 0)
		osmtpd_errx(1, "EVP_DigestUpdate");
}

const char *
ar_chain_status2str(enum ar_chain_status status)
{
	switch (status)
	{
	case AR_UNKNOWN:
		return "unknown";
	case AR_NONE:
		return "none";
	case AR_PASS:
		return "pass";
	case AR_FAIL:
		return "fail";
	}
}

void
sign_sign(struct osmtpd_ctx *ctx)
{
	struct message *message = ctx->local_message;
	/* Use largest hash size here */
	unsigned char bdigest[EVP_MAX_MD_SIZE];
	unsigned char digest[(((sizeof(bdigest) + 2) / 3) * 4) + 1];
	unsigned char *b;
	const char *sdomain = domain[0], *tsdomain;
	time_t now;
	ssize_t i;
	size_t linelen = 0;
	char *tmp, *tmp2;
	unsigned int digestsz;

	if ((mode == ARCSIGN || mode == ARCSEAL) &&
	    message->arc_i < ARC_MIN_I) {
		fprintf(stderr, "%016"PRIx64
		    " skip due to missed or invalid"
		    " ARC-Authentication-Results\n",
		    ctx->reqid);
		goto skip_sign;
	}

	if (mode == ARCSIGN || mode == ARCSEAL)
		signature_printf(message,
		    "i=%d; a=%s-%s; s=%s; ",
		    message->arc_i, cryptalg, hashalg, selector);

	if (mode == ARCSIGN)
		signature_printf(message, "c=%s/%s; ",
		    canonheader == CANON_SIMPLE ? "simple" : "relaxed",
		    canonbody == CANON_SIMPLE ? "simple" : "relaxed");

	if (mode == ARCSEAL)
		signature_printf(message, "cv=%s; ",
		    ar_chain_status2str(message->arc_cv));

	if (addtime || addexpire)
		now = time(NULL);
	if (addtime)
		signature_printf(message, "t=%lld; ", (long long)now);
	if ((mode == DKIMSIGN || mode == ARCSIGN) && addexpire != 0)
		signature_printf(message, "x=%lld; ",
		    now + addexpire < now ? LLONG_MAX : now + addexpire);

	if(mode == ARCSEAL)
		goto skip_seal;

	if (canonbody == CANON_SIMPLE && !message->has_body) {
		if (EVP_DigestUpdate(message->dctx, "\r\n", 2) <= 0)
			osmtpd_errx(1, "EVP_DigestUpdate");
	}
	if (EVP_DigestFinal_ex(message->dctx, bdigest, &digestsz) == 0)
		osmtpd_errx(1, "EVP_DigestFinal_ex");
	EVP_EncodeBlock(digest, bdigest, digestsz);
	signature_printf(message, "bh=%s; h=", digest);

skip_seal:
	/* Reverse order for ease of use of RFC6367 section 5.4.2 */
	for (i = 0; message->headers[i] != NULL; i++)
		continue;
	EVP_MD_CTX_reset(message->dctx);
	if (!sephash) {
		if (EVP_DigestSignInit(message->dctx, NULL, hash_md, NULL,
		    pkey) != 1)
			osmtpd_errx(1, "EVP_DigestSignInit");
	} else {
		if (EVP_DigestInit_ex(message->dctx, hash_md, NULL) != 1)
			osmtpd_errx(1, "EVP_DigestInit_ex");
	}
	for (i--; i >= 0; i--) {
		if (!sephash) {
			if (EVP_DigestSignUpdate(message->dctx,
			    message->headers[i],
			    strlen(message->headers[i])) != 1 ||
			    EVP_DigestSignUpdate(message->dctx, "\r\n",
			    2) <= 0)
				osmtpd_errx(1, "EVP_DigestSignUpdate");
		} else {
			if (EVP_DigestUpdate(message->dctx, message->headers[i],
			    strlen(message->headers[i])) != 1 ||
			    EVP_DigestUpdate(message->dctx, "\r\n", 2) <= 0)
				osmtpd_errx(1, "EVP_DigestSignUpdate");
		}
		if ((tsdomain = sign_domain_select(message, message->headers[i])) != NULL)
			sdomain = tsdomain;
		/* We're done with the cached header after hashing */
		for (tmp = message->headers[i]; tmp[0] != ':'; tmp++) {
			if (tmp[0] == ' ' || tmp[0] == '\t')
				break;
			tmp[0] = tolower(tmp[0]);
		}
		tmp[0] = '\0';
		if (mode == DKIMSIGN || mode == ARCSIGN)
			signature_printf(message, "%s%s",
			    message->headers[i + 1] == NULL  ? "" : ":",
			    message->headers[i]);
	}
	if (mode == DKIMSIGN || mode == ARCSIGN)
		signature_printf(message, "; d=%s; b=", sdomain);
	else if (mode == ARCSEAL)
		signature_printf(message, "d=%s; b=", sdomain);
	signature_normalize(message);
	if ((tmp = strdup(message->signature.signature)) == NULL)
		osmtpd_err(1, "strdup");
	sign_parse_header(message, tmp, 1);
	if (!sephash) {
		if (EVP_DigestSignUpdate(message->dctx, tmp,
		    strlen(tmp)) != 1)
			osmtpd_errx(1, "EVP_DigestSignUpdate");
	} else {
		if (EVP_DigestUpdate(message->dctx, tmp, strlen(tmp)) != 1)
			osmtpd_errx(1, "EVP_DigestUpdate");
	}
	free(tmp);
	if (!sephash) {
		if (EVP_DigestSignFinal(message->dctx, NULL, &linelen) != 1)
			osmtpd_errx(1, "EVP_DigestSignFinal");
	} else {
		if (EVP_DigestFinal_ex(message->dctx, bdigest,
		    &digestsz) != 1)
			osmtpd_errx(1, "EVP_DigestFinal_ex");
		EVP_MD_CTX_reset(message->dctx);
		if (EVP_DigestSignInit(message->dctx, NULL, NULL, NULL,
		    pkey) != 1)
			osmtpd_errx(1, "EVP_DigestSignInit");
		if (EVP_DigestSign(message->dctx, NULL, &linelen, bdigest,
		    digestsz) != 1)
			osmtpd_errx(1, "EVP_DigestSign");
	}
	if ((tmp = malloc(linelen)) == NULL)
		osmtpd_err(1, "malloc");
	if (!sephash) {
		if (EVP_DigestSignFinal(message->dctx, tmp, &linelen) != 1)
			osmtpd_errx(1, "EVP_DigestSignFinal");
	} else {
		if (EVP_DigestSign(message->dctx, tmp, &linelen, bdigest,
		    digestsz) != 1)
			osmtpd_errx(1, "EVP_DigestSign");
	}
	if ((b = malloc((((linelen + 2) / 3) * 4) + 1)) == NULL)
		osmtpd_err(1, "malloc");
	EVP_EncodeBlock(b, tmp, linelen);
	free(tmp);
	signature_printf(message, "%s\r\n", b);
	free(b);
	signature_normalize(message);
	tmp = message->signature.signature;
	while ((tmp2 = strchr(tmp, '\r')) != NULL) {
		tmp2[0] = '\0';
		osmtpd_filter_dataline(ctx, "%s", tmp);
		tmp = tmp2 + 2;
	}
skip_sign:
	tmp = NULL;
	linelen = 0;
	rewind(message->origf);
	while ((i = getline(&tmp, &linelen, message->origf)) != -1) {
		tmp[i - 1] = '\0';
		osmtpd_filter_dataline(ctx, "%s", tmp);
	}
	free(tmp);
	return;
}

void
signature_normalize(struct message *message)
{
	size_t i;
	size_t linelen;
	size_t checkpoint;
	size_t skip;
	size_t *headerlen = &(message->signature.len);
	int headername = 1;
	char tag = '\0';
	char *sig = message->signature.signature;

	for (linelen = i = 0; sig[i] != '\0'; i++) {
		if (sig[i] == '\r' && sig[i + 1] == '\n') {
			i++;
			checkpoint = 0;
			linelen = 0;
			continue;
		}
		if (sig[i] == '\t')
			linelen = (linelen + 8) & ~7;
		else
			linelen++;
		if (headername) {
			if (sig[i] == ':') {
				headername = 0;
				checkpoint = i;
			}
			continue;
		}
		if (linelen > SIGNATURE_LINELEN && checkpoint != 0) {
			for (skip = checkpoint + 1;
			    sig[skip] == ' ' || sig[skip] == '\t';
			    skip++)
				continue;
			skip -= checkpoint + 1;
			signature_need(message,
			    skip > 3 ? 0 : 3 - skip + 1);
			sig = message->signature.signature;

			memmove(sig + checkpoint + 3,
			    sig + checkpoint + skip,
			    *headerlen - skip - checkpoint + 1);
			sig[checkpoint + 1] = '\r';
			sig[checkpoint + 2] = '\n';
			sig[checkpoint + 3] = '\t';
			linelen = 8;
			*headerlen = *headerlen + 3 - skip;
			i = checkpoint + 3;
			checkpoint = 0;
		}
		if (sig[i] == ';') {
			checkpoint = i;
			tag = '\0';
			continue;
		}
		switch (tag) {
		case 'B':
		case 'b':
		case 'z':
			checkpoint = i;
			break;
		case 'h':
			if (sig[i] == ':')
				checkpoint = i;
			break;
		}
		if (tag == '\0' && sig[i] != ' ' && sig[i] != '\t') {
			if ((tag = sig[i]) == 'b' && sig[i + 1] == 'h' &&
			    sig[i + 2] == '=') {
				tag = 'B';
				linelen += 2;
				i += 2;
			} else
				tag = sig[i];
		}
	}
}

void
signature_printheader(struct message *message, const char *line)
{
	size_t i;
	int first;

	first = message->signature.signature[message->signature.len - 1] == '=';
	for (i = 0; line[i] != '\0'; i++) {
		if (i == 0 && line[i] != ' ' && line[i] != '\t' && !first)
			signature_printf(message, "|");
		if ((line[i] >= 0x21 && line[i] <= 0x3A) ||
		    (line[i] == 0x3C) ||
		    (line[i] >= 0x3E && line[i] <= 0x7B) ||
		    (line[i] >= 0x7D && line[i] <= 0x7E)) {
			signature_printf(message, "%c", line[i]);
		} else
			signature_printf(message, "=%02hhX", line[i]);
	}

	signature_printf(message, "=%02hhX=%02hhX", '\r', '\n');
}

void
signature_printf(struct message *message, char *fmt, ...)
{
	struct signature *sig = &(message->signature);
	va_list ap;
	size_t len;

	va_start(ap, fmt);
	if ((len = vsnprintf(sig->signature + sig->len, sig->size - sig->len,
	    fmt, ap)) >= sig->size - sig->len) {
		va_end(ap);
		signature_need(message, len + 1);
		va_start(ap, fmt);
		if ((len = vsnprintf(sig->signature + sig->len,
		    sig->size - sig->len, fmt, ap)) >= sig->size - sig->len)
			osmtpd_errx(1, "Miscalculated header size");
	}
	sig->len += len;
	va_end(ap);
}

const char *
sign_domain_select(struct message *message, char *from)
{
	char *mdomain0, *mdomain;
	size_t i;

	if ((mdomain = mdomain0 = osmtpd_mheader_from_domain(from)) == NULL)
		return NULL;

	while (mdomain != NULL && mdomain[0] != '\0') {
		for (i = 0; i < ndomains; i++) {
			if (strcasecmp(mdomain, domain[i]) == 0) {
				free(mdomain0);
				return domain[i];
			}
		}
		if ((mdomain = strchr(mdomain, '.')) != NULL)
			mdomain++;
	}
	free(mdomain0);
	return NULL;
}

void
signature_need(struct message *message, size_t len)
{
	struct signature *sig = &(message->signature);
	char *tmp;

	if (sig->len + len < sig->size)
		return;
	sig->size = (((len + sig->len) / 512) + 1) * 512;
	if ((tmp = realloc(sig->signature, sig->size)) == NULL)
		osmtpd_err(1, "malloc");
	sig->signature = tmp;
}

__dead void
usage(void)
{
	fprintf(stderr, "usage: filter-dkimsign [-tz] [-a signalg] "
	    "[-c canonicalization] \n    [-h headerfields] "
	    "[-x seconds] -D file -d domain -k keyfile -s selector\n");
	fprintf(stderr, "usage: filter-arcsign [-t] [-a signalg] "
	    "[-c canonicalization] \n    [-h headerfields] "
	    "[-x seconds] -D file -d domain -k keyfile -s selector\n");
	fprintf(stderr, "usage: filter-arcseal [-t] [-a signalg] "
	    "\n    [-x seconds] -D file -d domain -k keyfile "
	    "-s selector\n");
	exit(1);
}
