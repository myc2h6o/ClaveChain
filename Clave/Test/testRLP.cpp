#include "stdafx.h"
#include "CppUnitTest.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace TestRLP
{
    TEST_CLASS(TestLengthToHex) {
public:
    TEST_METHOD(TestLength_0) {
        assertEqualHexLength(NULL, 0, 0);
    }
    TEST_METHOD(TestLength_1) {
        unsigned char c_01[] = { 0x01 };
        assertEqualHexLength(c_01, 1, 1);
    }
    TEST_METHOD(TestLength_2) {
        unsigned char c_02[] = { 0x02 };
        assertEqualHexLength(c_02, 1, 2);
    }
    TEST_METHOD(TestLength_45) {
        unsigned char c_45[] = { 0x45 };
        assertEqualHexLength(c_45, 1, 0x45);
    }
    TEST_METHOD(TestLength_2_bytes) {
        unsigned char c_0456[] = { 0x04, 0x56 };
        assertEqualHexLength(c_0456, 2, 0x456);
    }
    TEST_METHOD(TestLength_full_bytes) {
        unsigned char c_14002400[] = { 0x14, 0x00, 0x24, 0x00 };
        assertEqualHexLength(c_14002400, 4, 0x14002400);
    }
    TEST_METHOD(TestLength_max) {
        unsigned char c_ffffffff[] = { 0xff, 0xff, 0xff, 0xff };
        assertEqualHexLength(c_ffffffff, 4, 0xffffffff);
    }
private:
    void assertEqualHexLength(const unsigned char *expected, const unsigned int& expectedLength, const unsigned int& length) {
        unsigned char *hexLength = NULL;
        unsigned int size = RLP::lengthToHex(&hexLength, length);
        if (0 != memcmp(expected, hexLength, expectedLength)) {
            free(hexLength);
            Assert::Fail();
        }
        free(hexLength);
    }
    };

    TEST_CLASS(TestEncodeLength) {
public:
    TEST_METHOD(TestStringOffset_0) {
        unsigned char c_80[] = { 0x80 };
        assertEqualEncodedLength(c_80, 1, STRING_OFFSET, 0);
    }
    TEST_METHOD(TestStringOffset_1) {
        unsigned char c_81[] = { 0x81 };
        assertEqualEncodedLength(c_81, 1, STRING_OFFSET, 1);
    }
    TEST_METHOD(TestStringOffset_2) {
        unsigned char c_82[] = { 0x82 };
        assertEqualEncodedLength(c_82, 1, STRING_OFFSET, 2);
    }
    TEST_METHOD(TestStringOffset_short_max) {
        unsigned char c_b7[] = { 0xb7 };
        assertEqualEncodedLength(c_b7, 1, STRING_OFFSET, 0x37);
    }
    TEST_METHOD(TestStringOffset_long_min) {
        unsigned char c_b838[] = { 0xb8, 0x38 };
        assertEqualEncodedLength(c_b838, 2, STRING_OFFSET, 0x38);
    }
    TEST_METHOD(TestStringOffset_long) {
        unsigned char c_b850[] = { 0xb8, 0x50 };
        assertEqualEncodedLength(c_b850, 2, STRING_OFFSET, 0x50);
    }
    TEST_METHOD(TestStringOffset_long_2byes) {
        unsigned char c_b90400[] = { 0xb9, 0x04, 0x00 };
        assertEqualEncodedLength(c_b90400, 3, STRING_OFFSET, 1024);
    }
    TEST_METHOD(TestStringOffset_long_max) {
        unsigned char c_bbffffffff[] = { 0xbb, 0xff, 0xff, 0xff, 0xff };
        assertEqualEncodedLength(c_bbffffffff, 5, STRING_OFFSET, UINT32_MAX);
    }
    TEST_METHOD(TestArrayOffset_0) {
        unsigned char c_c0[] = { 0xc0 };
        assertEqualEncodedLength(c_c0, 1, ARRAY_OFFSET, 0);
    }
    TEST_METHOD(TestArrayOffset_1) {
        unsigned char c_c1[] = { 0xc1 };
        assertEqualEncodedLength(c_c1, 1, ARRAY_OFFSET, 1);
    }
    TEST_METHOD(TestArrayOffset_2) {
        unsigned char c_c2[] = { 0xc2 };
        assertEqualEncodedLength(c_c2, 1, ARRAY_OFFSET, 2);
    }
    TEST_METHOD(TestArrayOffset_short_max) {
        unsigned char c_f7[] = { 0xf7 };
        assertEqualEncodedLength(c_f7, 1, ARRAY_OFFSET, 0x37);
    }
    TEST_METHOD(TestArrayOffset_long_min) {
        unsigned char c_f838[] = { 0xf8, 0x38 };
        assertEqualEncodedLength(c_f838, 2, ARRAY_OFFSET, 0x38);
    }
    TEST_METHOD(TestArrayOffset_long) {
        unsigned char c_f850[] = { 0xf8, 0x50 };
        assertEqualEncodedLength(c_f850, 2, ARRAY_OFFSET, 0x50);
    }
    TEST_METHOD(TestArrayOffset_long_2byes) {
        unsigned char c_f90400[] = { 0xf9, 0x04, 0x00 };
        assertEqualEncodedLength(c_f90400, 3, ARRAY_OFFSET, 1024);
    }
    TEST_METHOD(TestArrayOffset_long_max) {
        unsigned char c_fbffffffff[] = { 0xfb, 0xff, 0xff, 0xff, 0xff };
        assertEqualEncodedLength(c_fbffffffff, 5, ARRAY_OFFSET, UINT32_MAX);
    }
private:
    const int ARRAY_OFFSET = 0xc0;
    const int STRING_OFFSET = 0x80;
    void assertEqualEncodedLength(const unsigned char *expected, const unsigned int &expectedLength, const unsigned int &offset, const unsigned int &length) {
        unsigned char *encodedLength = NULL;
        unsigned int actualLength = RLP::encodeLength(&encodedLength, offset, length);
        Assert::AreEqual(expectedLength, actualLength);
        if (0 != memcmp(expected, encodedLength, expectedLength)) {
            free(encodedLength);
            Assert::Fail();
        }
        free(encodedLength);
    }
    };

    TEST_CLASS(TestEncodeString) {
public:
    TEST_METHOD(TestEmptyString) {
        unsigned char c_80[] = { 0x80 };
        assertEqualEncodedString(c_80, 1, (unsigned char*)"", 0);
    }
    TEST_METHOD(TestStringLength_1_byteNormal) {
        unsigned char c_a[] = { 'a' };
        assertEqualEncodedString(c_a, 1, (unsigned char*)"a", 1);
    }
    TEST_METHOD(TestStringLength_1_byteMaxNormal) {
        unsigned char c_79[] = { 0x79 };
        assertEqualEncodedString(c_79, 1, c_79, 1);
    }
    TEST_METHOD(TestStringLength_1_byteMinExtend) {
        unsigned char c_8180[] = { 0x81, 0x80 };
        unsigned char c_80[] = { 0x80 };
        assertEqualEncodedString(c_8180, 2, c_80, 1);
    }
    TEST_METHOD(TestStringLength_1_byteExtend) {
        unsigned char c_8181[] = { 0x81, 0x81 };
        unsigned char c_81[] = { 0x81 };
        assertEqualEncodedString(c_8181, 2, c_81, 1);
    }
    TEST_METHOD(TestStringLength_2) {
        unsigned char c_82ab[] = { 0x82, 'a', 'b' };
        assertEqualEncodedString(c_82ab, 3, (unsigned char*)"ab", 2);
    }
    TEST_METHOD(TestStringLength_maxNormal) {
        unsigned char buf[0x37] = "This string is 55 bytes long including the ending zero";
        unsigned char expected[0x38];
        expected[0] = 0xb7;
        memcpy(expected + 1, buf, 0x37);
        assertEqualEncodedString(expected, 0x38, buf, 0x37);
    }
    TEST_METHOD(TestStringLength_minExtend) {
        unsigned char buf[0x38] = "This string is 56 bytes long including the ending zero!";
        unsigned char expected[0x3a];
        expected[0] = 0xb8;
        expected[1] = 0x38;
        memcpy(expected + 2, buf, 0x38);
        assertEqualEncodedString(expected, 0x3a, buf, 0x38);
    }
    TEST_METHOD(TestStringLength_extend) {
        unsigned char buf[0x40] = "This string is 64 bytes( 0x40 ) long including the ending zero!";
        unsigned char expected[0x42];
        expected[0] = 0xb8;
        expected[1] = 0x40;
        memcpy(expected + 2, buf, 0x40);
        assertEqualEncodedString(expected, 0x42, buf, 0x40);
    }
    TEST_METHOD(TestStringLength_twoBytes) {
        unsigned char partBuf[0x40] = "This string is 64 bytes( 0x40 ) long including the ending zero!";
        unsigned char buf[0x100];
        memcpy(buf, partBuf, 0x40);
        memcpy(buf + 0x40, partBuf, 0x40);
        memcpy(buf + 0x80, partBuf, 0x40);
        memcpy(buf + 0xc0, partBuf, 0x40);
        unsigned char expected[0x103];
        expected[0] = 0xb9;
        expected[1] = 0x01;
        expected[2] = 0x00;
        memcpy(expected + 3, buf, 0x100);
        assertEqualEncodedString(expected, 0x103, buf, 0x100);
    }
    TEST_METHOD(TestStringLength_longString) {
        const unsigned int length = 0x10001;
        unsigned char buf[length];
        unsigned char expected[length + 4];
        for (unsigned int i = 0; i < length; ++i) {
            buf[i] = i;
            expected[i + 4] = i;
        }
        expected[0] = 0xba;
        expected[1] = 0x01;
        expected[2] = 0x00;
        expected[3] = 0x01;
        assertEqualEncodedString(expected, length + 4, buf, length);
    }
private:
    void assertEqualEncodedString(const unsigned char *expected, const unsigned int &expectedLength, const unsigned char *input, const unsigned int &inputLength) {
        unsigned char *encodedString = NULL;
        unsigned int actualLength = RLP::encodeString(&encodedString, input, inputLength);
        Assert::AreEqual(expectedLength, actualLength);
        if (0 != memcmp(expected, encodedString, expectedLength)) {
            free(encodedString);
            Assert::Fail();
        }
        free(encodedString);
    }
    };

    TEST_CLASS(TestEncodingArray) {
public:
    TEST_METHOD(TestArraySize_0) {
        unsigned char *output = NULL;
        unsigned int length = RLP::encodeArray(&output, NULL, 0);
        Assert::IsNull(output);
        Assert::AreEqual((unsigned int)0, length);
    }
    TEST_METHOD(TestArraySize_1_StringLength_0) {
        unsigned char c_c180[] = { 0xc1, 0x80 };
        RLPStringItem items[1];
        items[0].str = (unsigned char*)"";
        items[0].length = 0;
        assertEqualEncodedArray(c_c180, 2, items, 1);
    }
    TEST_METHOD(TestArraySize_1_StringLength_3){
        unsigned char expected[] = { 0xc4, 0x83, 'c', 'a', 't' };
        RLPStringItem items[1];
        items[0].str = (unsigned char*)"cat";
        items[0].length = 3;
        assertEqualEncodedArray(expected, 5, items, 1);
    }
    TEST_METHOD(TestArraySize_2) {
        unsigned char expected[] = { 0xc9, 0x83, 'c', 'a', 't', 0x84, 'l', 'i', 'o', 'n' };
        RLPStringItem items[2];
        items[0].str = (unsigned char*)"cat";
        items[0].length = 3;
        items[1].str = (unsigned char*)"lion";
        items[1].length = 4;
        assertEqualEncodedArray(expected, 10, items, 2);
    }
    TEST_METHOD(TestEmptyStringStartMiddleEnd) {
        unsigned char expected[] = { 0xcc, 0x80, 0x83, 'c', 'a', 't', 0x80, 0x84, 'l', 'i', 'o', 'n', 0x80 };
        RLPStringItem items[5];
        items[0].length = 0;
        items[1].str = (unsigned char*)"cat";
        items[1].length = 3;
        items[2].length = 0;
        items[3].str = (unsigned char*)"lion";
        items[3].length = 4;
        items[4].length = 0;
        assertEqualEncodedArray(expected, 13, items, 5);
    }
    TEST_METHOD(TestMaxNormalLength) {
        unsigned char buf[0x32] = "This string is 50 bytes long and is ended by zero";
        RLPStringItem items[2];
        items[0].str = buf;
        items[0].length = 0x32;
        items[1].str = (unsigned char*)"cat";
        items[1].length = 3;
        unsigned char expected[0x38];
        expected[0] = 0xf7;
        expected[1] = 0xb2;
        memcpy(expected + 2, items[0].str, 0x32);
        expected[0x34] = 0x83;
        memcpy(expected + 0x35, items[1].str, 3);

        assertEqualEncodedArray(expected, 0x38, items, 2);
    }
    TEST_METHOD(TestMinExtendLength) {
        unsigned char buf[0x32] = "This string is 50 bytes long and is ended by zero";
        RLPStringItem items[2];
        items[0].str = buf;
        items[0].length = 0x32;
        items[1].str = (unsigned char*)"lion";
        items[1].length = 4;
        unsigned char expected[0x3a];
        expected[0] = 0xf8;
        expected[1] = 0x38;
        expected[2] = 0xb2;
        memcpy(expected + 3, items[0].str, 0x32);
        expected[0x35] = 0x84;
        memcpy(expected + 0x36, items[1].str, 4);

        assertEqualEncodedArray(expected, 0x3a, items, 2);
    }
    TEST_METHOD(TestExtendLength) {
        unsigned char buf[0x40] = "This string is 64 bytes( 0x40 ) long including the ending zero!";
        RLPStringItem items[2];
        items[0].str = buf;
        items[0].length = 0x40;
        items[1].str = (unsigned char*)"lion";
        items[1].length = 4;
        unsigned char expected[0x49];
        expected[0] = 0xf8;
        expected[1] = 0x47;
        expected[2] = 0xb8;
        expected[3] = 0x40;
        memcpy(expected + 4, items[0].str, 0x40);
        expected[0x44] = 0x84;
        memcpy(expected + 0x45, items[1].str, 4);

        assertEqualEncodedArray(expected, 0x49, items, 2);
    }
    TEST_METHOD(TestTwoBytesLength) {
        unsigned char buf[0x40] = "This string is 64 bytes( 0x40 ) long including the ending zero!";
        RLPStringItem items[4];
        for (int i = 0; i < 4; ++i) {
            items[i].str = buf;
            items[i].str[0x20] = i;
            items[i].length = 0x40;
        }

        unsigned char expected[0x10b];
        expected[0] = 0xf9;
        expected[1] = 0x01;
        expected[2] = 0x08;

        expected[3] = 0xb8;
        expected[4] = 0x40;
        memcpy(expected + 5, items[0].str, 0x40);
        expected[0x45] = 0xb8;
        expected[0x46] = 0x40;
        memcpy(expected + 0x47, items[1].str, 0x40);
        expected[0x87] = 0xb8;
        expected[0x88] = 0x40;
        memcpy(expected + 0x89, items[2].str, 0x40);
        expected[0xc9] = 0xb8;
        expected[0xca] = 0x40;
        memcpy(expected + 0xcb, items[3].str, 0x40);

        assertEqualEncodedArray(expected, 0x10b, items, 4);
    }
    TEST_METHOD(TestLongArray) {
        const unsigned int length = 0x10001;
        unsigned char buf[length];
        unsigned char expected[length + 8];
        for (unsigned int i = 0; i < length; ++i) {
            buf[i] = i;
            expected[i + 8] = i;
        }

        RLPStringItem items[1];
        items[0].str = buf;
        items[0].length = length;

        expected[0] = 0xfa;
        expected[1] = 0x01;
        expected[2] = 0x00;
        expected[3] = 0x05;
        expected[4] = 0xba;
        expected[5] = 0x01;
        expected[6] = 0x00;
        expected[7] = 0x01;
        assertEqualEncodedArray(expected, length + 8, items, 1);
    }
private:
    void assertEqualEncodedArray(const unsigned char *expected, const unsigned int& expectedLength, const RLPStringItem *input, const unsigned int& size) {
        unsigned char *encodedArray = NULL;
        unsigned int actualLength = RLP::encodeArray(&encodedArray, input, size);
        Assert::AreEqual(expectedLength, actualLength);
        if (0 != memcmp(expected, encodedArray, expectedLength)) {
            free(encodedArray);
            Assert::Fail();
        }
        free(encodedArray);
    }
    };
}
