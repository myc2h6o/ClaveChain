#ifndef _NET_H_
#define _NET_H_

/*
 * return:
 *   data generating by malloc()
 *   empty string if cannnot get data from uri
 * return data is ended by '\0'
 */
char *getDataFromUri(const char *uri);

#endif
