#ifndef _CHAIN_H_
#define _CHAIN_H_

#include <vector>
#include "Enclave_u.h"
#define CURL_STATICLIB
#include "curl/curl.h"

struct Request {
    std::string uri;
    bool isDone;
};

class Chain {
public:
    static void init();
    static void destroy();
    static std::vector<Request> getRequests();
    static int callContract(const std::string& signedTransaction);
    static void increaseId() { currentId++; }
private:
    static unsigned long long currentId;
    static unsigned long long getRemoteId();
    static Request getRequest(const unsigned long long& id);
    static CURLcode curlPostJson(std::string json);
    static size_t WriteMemoryCallback(char *src, size_t size, size_t nmemb, std::string *dst);
};

#endif
