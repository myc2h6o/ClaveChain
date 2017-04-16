#ifndef _OUTER_DATA_H_
#define _OUTER_DATA_H_

#define OUTER_DATA_NAME_SIZE 32
#define OUTER_DATA_PHONE_SIZE 32

/*
 * get data from trusted outer source and set name and phone
 * set name and phone to empty string if cannot get data
 */
void getCustomerInfo(const char *index, char name[OUTER_DATA_NAME_SIZE + 1], char phone[OUTER_DATA_PHONE_SIZE + 1]);

#endif
