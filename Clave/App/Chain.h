#ifndef _CHAIN_H_
#define _CHAIN_H_

#include <vector>
#include "Enclave_u.h"
#define CURL_STATICLIB
#include "curl/curl.h"

enum T_CallContract {
    CALL_CONTRACT_OK,
    CALL_CONTRACT_FAIL,
    CALL_CONTRACT_NONCE_TOO_LOW
};

struct Request {
    unsigned long long id;
    std::string uri;
    bool isDone;
};

class Chain {
public:
    static void init(const std::string& _host, const std::string& _address);
    static void destroy();
    static std::vector<Request> getRequests();
    static T_CallContract callContract(const std::string& signedTransaction);
    static void increaseId() { currentId++; }
    static void increaseNonce() { nonce++; }
    static std::string getHexNonce();
private:
    static std::string address;
    static unsigned long long nonce;
    static unsigned long long currentId;
    static unsigned long long getRemoteId();
    static Request getRequest(const unsigned long long& id);
    static CURLcode curlPostJson(std::string json);
    static size_t WriteMemoryCallback(char *src, size_t size, size_t nmemb, std::string *dst);
};

#endif
