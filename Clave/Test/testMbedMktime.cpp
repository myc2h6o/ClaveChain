#include "stdafx.h"
#include "CppUnitTest.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

typedef uint64_t sgx_time_t;
typedef struct mbedtls_x509_time
{
    int year, mon, day;
    int hour, min, sec;
} mbedtls_x509_time;

sgx_time_t mbedMktime(const mbedtls_x509_time *t);

namespace TestMbedMktime
{
    TEST_CLASS(TestMbedMktime) {
public:
    TEST_METHOD(Sample) {
        // [TODO] Use system mktime for check
        Assert::AreEqual((sgx_time_t)0, mbedMktime(NULL));
    }
private:
    };
}
