#include "stdafx.h"
#include "CppUnitTest.h"
#include <time.h>

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

typedef uint64_t sgx_time_t;
typedef struct mbedtls_x509_time
{
    int year, mon, day;
    int hour, min, sec;
} mbedtls_x509_time;

sgx_time_t mbedMktime(const mbedtls_x509_time *t);

#define TIME_ZONE 8
#define SEC_OFFSET (TIME_ZONE * 3600)

namespace TestMbedMktime
{
    TEST_CLASS(TestMbedMktime) {
public:
    TEST_METHOD(BaseTime) {
        testTime(1970, 1, 1, 0, 0, 0);
    }
    TEST_METHOD(MinMonth) {
        testTime(2017, 1, 15, 15, 15, 15);
    }
    TEST_METHOD(MiddleMonth) {
        testTime(2017, 8, 15, 15, 15, 15);
    }
    TEST_METHOD(MaxMonth) {
        testTime(2017, 12, 15, 15, 15, 15);
    }
    TEST_METHOD(MinDay) {
        testTime(2017, 8, 1, 15, 15, 15);
    }
    TEST_METHOD(MiddleDay) {
        testTime(2017, 8, 20, 15, 15, 15);
    }
    TEST_METHOD(MaxDay) {
        testTime(2017, 8, 31, 15, 15, 15);
    }
    TEST_METHOD(MinHour) {
        testTime(2017, 8, 20, 0, 15, 15);
    }
    TEST_METHOD(MiddleHour) {
        testTime(2017, 8, 20, 12, 15, 15);
    }
    TEST_METHOD(MaxHour) {
        testTime(2017, 8, 20, 23, 15, 15);
    }
    TEST_METHOD(MinMinute) {
        testTime(2017, 8, 20, 12, 0, 15);
    }
    TEST_METHOD(MiddleMinute) {
        testTime(2017, 8, 20, 12, 30, 15);
    }
    TEST_METHOD(MaxMinute) {
        testTime(2017, 8, 20, 12, 59, 15);
    }
    TEST_METHOD(MinSecond) {
        testTime(2017, 8, 20, 12, 0, 0);
    }
    TEST_METHOD(MiddleSecond) {
        testTime(2017, 8, 20, 12, 0, 30);
    }
    TEST_METHOD(MaxSecond) {
        testTime(2017, 8, 20, 12, 0, 59);
    }
    TEST_METHOD(LeapYearBeforeFeb) {
        testTime(2016, 1, 20, 12, 12, 12);
    }
    TEST_METHOD(LeapYearFeb) {
        testTime(2016, 2, 29, 12, 12, 12);
    }
    TEST_METHOD(LeapYearAfterFeb) {
        testTime(2016, 3, 2, 12, 12, 12);
    }
    TEST_METHOD(NonLeapYearBeforeFeb) {
        testTime(2015, 1, 10, 12, 12, 12);
    }
    TEST_METHOD(NonLeapYearFeb) {
        testTime(2015, 2, 28, 12, 12, 12);
    }
    TEST_METHOD(NonLeapYearAfterFeb) {
        testTime(2015, 3, 4, 12, 12, 12);
    }

private:
    void testTime(const int& year, const int& month, const int& day, const int& hour, const int& minute, const int& second) {
        mbedtls_x509_time m = mbedTime(year, month, day, hour, minute, second);
        time_t t = mbedTimeToTimeT(m);
        Assert::AreNotEqual((sgx_time_t)-1, (sgx_time_t)t);
        sgx_time_t sgxTime = mbedMktime(&m);
        Assert::AreEqual((sgx_time_t)t, sgxTime);
    }

    mbedtls_x509_time mbedTime(const int& year, const int& month, const int& day, const int& hour, const int& minute, const int& second) {
        mbedtls_x509_time result;
        result.year = year;
        result.mon = month;
        result.day = day;
        result.hour = hour;
        result.min = minute;
        result.sec = second;
        return result;
    }

    time_t mbedTimeToTimeT(mbedtls_x509_time& m) {
        tm t;
        t.tm_year = m.year - 1900;
        t.tm_mon = m.mon - 1;
        t.tm_mday = m.day;
        t.tm_hour = m.hour;
        t.tm_min = m.min;
        t.tm_sec = m.sec;
        t.tm_isdst = 0;
        time_t result;
        result = mktime(&t);
        if (result < 0) {
            t.tm_hour += TIME_ZONE;
            result = mktime(&t);
        }
        else {
            result += SEC_OFFSET;
        }
        return result;
    }
    };
}
