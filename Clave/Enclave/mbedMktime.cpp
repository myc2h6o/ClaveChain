#include "mbedMktime.h"

#define MIN_YEAR 1970
#define DAY_SECOND (3600 * 24)
#define LEAP_YEAR_SECOND (366 * DAY_SECOND)
#define NON_LEAP_YEAR_SECOND  (365 * DAY_SECOND)
#define N_PAST_LEAP(x) ((x) / 4 + (x) / 400 - (x) / 100)
const int LEAP_MONTH_SECOND[] = {
    0,
    DAY_SECOND * 31,
    DAY_SECOND * 60,
    DAY_SECOND * 91,
    DAY_SECOND * 121,
    DAY_SECOND * 152,
    DAY_SECOND * 182,
    DAY_SECOND * 213,
    DAY_SECOND * 244,
    DAY_SECOND * 274,
    DAY_SECOND * 305,
    DAY_SECOND * 335
};
const int NON_LEAP_MONTH_SECOND[] = {
    0,
    DAY_SECOND * 31,
    DAY_SECOND * 59,
    DAY_SECOND * 90,
    DAY_SECOND * 120,
    DAY_SECOND * 151,
    DAY_SECOND * 181,
    DAY_SECOND * 212,
    DAY_SECOND * 243,
    DAY_SECOND * 273,
    DAY_SECOND * 304,
    DAY_SECOND * 334
};

bool isLeapYear(int year) {
    if (year % 400 == 0) {
        return true;
    }
    else if (year % 100 == 0) {
        return false;
    }
    else if (year % 4 == 0) {
        return true;
    }
    else {
        return false;
    }
}

// return count of leap year since MIN_YEAR(including year)
int nLeapYear(int year) {
    return N_PAST_LEAP(year - 1) - N_PAST_LEAP(MIN_YEAR - 1);
}

int yearSecond(int year) {
    int leap = nLeapYear(year);
    int nonLeap = year - MIN_YEAR - leap;
    return leap * LEAP_YEAR_SECOND + nonLeap * NON_LEAP_YEAR_SECOND;
}

int monthSecond(int year, int month) {
    if (isLeapYear(year)) {
        return LEAP_MONTH_SECOND[month];
    }
    else {
        return NON_LEAP_MONTH_SECOND[month];
    }
}

int daySecond(int day) {
    return day * 24 * 3600;
}

sgx_time_t mbedMktime(const mbedtls_x509_time *t) {
    if (t->year < MIN_YEAR) {
        return -1;
    }
    sgx_time_t result = 0;
    result += yearSecond(t->year);
    result += monthSecond(t->year, t->mon - 1);
    result += daySecond(t->day - 1);
    result += t->hour * 3600;
    result += t->min * 60;
    result += t->sec;
    return result;
}
