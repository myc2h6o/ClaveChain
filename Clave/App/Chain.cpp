#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <string>
#include "Chain.h"

#define HEX_PREFIX_OFFSET 2
#define RESULT_OFFSET 9
#define HEX_UINT64_OFFSET 48
#define HEX_UINT64_SIZE 16
#define HEX_UINT256_SIZE 64
#define HEX_BOOL_OFFSET 63
#define HEX_BOOL_SIZE 1

CURL *curl = NULL;
curl_slist *header = NULL;
std::string curlRetData = "";

unsigned long long Chain::currentId = 0;
unsigned long long Chain::nonce = 1;
std::string Chain::address = "";

void Chain::init(const std::string& _host, const std::string& _address) {
    address = _address;
    curl_global_init(CURL_GLOBAL_ALL);
    curl = curl_easy_init();
    curl_easy_setopt(curl, CURLOPT_URL, _host.c_str());
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "libcurl-agent/1.0");
    header = curl_slist_append(NULL, "Content-Type:application/json;charset=UTF-8");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, header);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &curlRetData);
    curlRetData = "";
}

void Chain::destroy() {
    curl_slist_free_all(header);
    curl_easy_cleanup(curl);
    curl_global_cleanup();
}

/*
 * getRequests: get pending requests from blockchain
 * return: pending requests, size equals zero when there are no pending requests
 * throw Exception: when failing to reach blockchain server
 */
std::vector<Request> Chain::getRequests() {
    std::vector<Request> result;
    unsigned long long localId = currentId;
    unsigned long long remoteId = getRemoteId();
    while (localId != remoteId) {
        Request request = getRequest(localId);
        result.push_back(request);
        localId++;
    }
    return result;
}

/*
 * callContract: call contract on blockchain
 * signedTransaction: signed transaction for calling contract
 * return:
 *   CALL_CONTRACT_OK: succeed
 *   CALL_CONTRACT_FAIL: fail
 *   CALL_CONTRACT_NONCE_TOO_LOW: nonce too low
 */
T_CallContract Chain::callContract(const std::string& signedTransaction) {
    std::string json = "{\"jsonrpc\":\"2.0\",\"method\":\"eth_sendRawTransaction\",\"params\":[\"0x";
    json += signedTransaction;
    json += "\"],\"id\":1}";
    int ret = curlPostJson(json);
    if (ret != CURLE_OK) {
        return CALL_CONTRACT_FAIL;
    }

    // nonce too low
    int pos = curlRetData.find("Nonce too low");
    if (pos != -1) {
        return CALL_CONTRACT_NONCE_TOO_LOW;
    }

    // print transaction hash
    pos = curlRetData.find("result");
    if (pos == -1) {
        // unknown return error
        std::cout << curlRetData;
        return CALL_CONTRACT_OK;
    }
    pos += RESULT_OFFSET;
    int posR = curlRetData.find('"', pos);
    if (posR == -1) {
        return CALL_CONTRACT_OK;
    }
    std::cout << "Tx Hash: " << curlRetData.substr(pos, posR - pos) << std::endl;

    return CALL_CONTRACT_OK;
}

/*
 * return id on remote chain
 * return currentId if cannot get remote id
 */
unsigned long long Chain::getRemoteId() {
    std::string json = "{\"jsonrpc\":\"2.0\",\"method\":\"eth_call\",\"params\":[{\"to\":\"0x";
    json += address;
    json += "\",\"data\":\"0xe00dd161\"},\"latest\"],\"id\":1}";
    int ret = curlPostJson(json);
    if (ret != CURLE_OK) {
        return currentId;
    }

    int pos = curlRetData.find("result");
    if (pos == -1) {
        return currentId;
    }

    unsigned long long remoteId = 0;
    pos += RESULT_OFFSET + HEX_PREFIX_OFFSET + HEX_UINT64_OFFSET;
    std::string id = curlRetData.substr(pos, HEX_UINT64_SIZE);
    sscanf_s(id.c_str(), "%llx", &remoteId);
    return remoteId;
}

Request Chain::getRequest(const unsigned long long& id) {
    Request result;
    result.id = id;
    result.isDone = true;
    result.uri = "";

    // get request json
    char hexId[HEX_UINT64_SIZE + 1];
    sprintf_s(hexId, "%016llx", id);

    std::string json = "{\"jsonrpc\":\"2.0\",\"method\":\"eth_call\",\"params\":[{\"to\":\"0x";
    json += address;
    json += "\",\"data\":\"0x411010ec000000000000000000000000000000000000000000000000";
    json += hexId;
    json += "\"},\"latest\"],\"id\":1}";
    int ret = curlPostJson(json);
    if (ret != CURLE_OK) {
        return result;
    }

    // find result
    int pos = curlRetData.find("result");
    if (pos == -1) {
        return result;
    }

    // get isDone
    pos += RESULT_OFFSET + HEX_PREFIX_OFFSET + HEX_UINT256_SIZE * 3 + HEX_BOOL_OFFSET;
    if (curlRetData[pos] == '0') {
        result.isDone = false;
    }

    // get uri length
    pos += HEX_BOOL_SIZE + HEX_UINT64_OFFSET;
    std::string hexUriLength = curlRetData.substr(pos, HEX_UINT64_SIZE);
    unsigned long long  uriLength = 0;
    sscanf_s(hexUriLength.c_str(), "%llx", &uriLength);

    // get uri
    pos += HEX_UINT64_SIZE;
    std::string hexUri = curlRetData.substr(pos, uriLength * 2);
    result.uri.resize(uriLength);
    for (unsigned long long i = 0; i < uriLength; ++i) {
        sscanf_s(hexUri.substr(2 * i, 2).c_str(), "%x", &(result.uri[i]));
    }

    return result;
}

CURLcode Chain::curlPostJson(std::string json) {
    CURLcode res;
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json.c_str());
    res = curl_easy_perform(curl);
    return res;
}

size_t Chain::WriteMemoryCallback(char *src, size_t size, size_t nmemb, std::string *dst) {
    size_t length = size * nmemb;
    *dst = std::string(src, length);
    return length;
}

std::string Chain::getHexNonce() {
    char buf[HEX_UINT64_SIZE];
    sprintf_s(buf, "%llx", nonce);
    std::string result = std::string(buf);
    return result;
}
