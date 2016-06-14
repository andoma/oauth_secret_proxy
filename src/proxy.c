#include <string.h>
#include <stdio.h>
#include <limits.h>

#include "libsvc/http.h"
#include "libsvc/htsmsg_json.h"
#include "libsvc/misc.h"
#include "libsvc/trace.h"
#include "libsvc/cfg.h"
#include "libsvc/db.h"
#include "libsvc/curlhelpers.h"
#include "libsvc/memstream.h"
#include "libsvc/talloc.h"

#include "proxy.h"


static int
proxy(http_connection_t *hc, const char *remain,
      void *opaque)
{
  cfg_root(root);

  const char *referer = http_arg_get(&hc->hc_args, "referer");
  if(referer == NULL || strcmp(referer, "https://movian.tv/"))
    return 403;

  const char *client_id = http_arg_get(&hc->hc_req_args, "client_id");
  const char *url_id = http_arg_get(&hc->hc_args, "X-URL-ID");
  const char *secret = NULL;
  const char *url = NULL;
  if(client_id == NULL)
    return 400;

  for(int i = 0; ; i++) {
    const char *cid = cfg_get_str(root, CFG("clients", CFG_INDEX(i), "id"), NULL);
    if(cid == NULL)
      break;
    if(!strcmp(client_id, cid)) {
      secret = cfg_get_str(root, CFG("clients", CFG_INDEX(i), "secret"), NULL);
      if (url_id == NULL)
        url = cfg_get_str(root, CFG("clients", CFG_INDEX(i), "url"), NULL);
      else {
        for(int j = 0; ; j++) {
          const char *uid = cfg_get_str(root, CFG("clients", CFG_INDEX(i), "urls", CFG_INDEX(j), "id"), NULL);
          if(uid == NULL)
            break;
          if(!strcmp(url_id, uid)) {
            url = cfg_get_str(root, CFG("clients", CFG_INDEX(i), "urls", CFG_INDEX(j), "url"), NULL);
            break;
          }
        }
      }
      break;
    }
  }

  if(secret == NULL || url == NULL)
    return 404;

  const char *postdata =
    tsprintf("client_secret=%s", url_escape_tmp(secret, URL_ESCAPE_PARAM));

  http_arg_t *ha;
  TAILQ_FOREACH(ha, &hc->hc_req_args, link) {
    postdata = tsprintf("%s&%s=%s",
                        postdata,
                        url_escape_tmp(ha->key, URL_ESCAPE_PARAM),
                        url_escape_tmp(ha->val, URL_ESCAPE_PARAM));
  }

  char *out;
  size_t outlen;
  FILE *f = open_buffer(&out, &outlen);

  struct curl_slist *slist = NULL;

  CURL *curl = curl_easy_init();
  curl_easy_setopt(curl, CURLOPT_URL, url);
  curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, f);
  curl_easy_setopt(curl, CURLOPT_USERAGENT, "Oauth Secret Proxy");
  curl_easy_setopt(curl, CURLOPT_POST, 1L);
  curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postdata);
  curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)strlen(postdata));

  slist = curl_slist_append(slist, "Accept: application/json");


  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, slist);

  CURLcode result = curl_easy_perform(curl);
  curl_slist_free_all(slist);


  fwrite("", 1, 1, f);
  fclose(f);

  if(result) {
    curl_easy_cleanup(curl);
    free(out);
    return 502;
  }

  long http_code = 0;
  curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
  htsbuf_append(&hc->hc_reply, out, strlen(out));
  free(out);
  curl_easy_cleanup(curl);
  return http_send_reply(hc, http_code, "application/json", NULL, NULL, 0);
}


void
proxy_init(void)
{
  http_path_add("/token", NULL, proxy);
}
