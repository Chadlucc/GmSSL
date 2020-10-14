# SM3 algorithm function interface:

## sm3\_string(const unsigned char\* msg, size\_t msglen, unsigned char dgst\[SM3\_DIGEST\_LENGTH\])

The parameters of the function are the first address of the message, the length of the message and the address of the output hash value.

## sm3\_speed();

Function output speed of SM3 algorithm.

## int sm3\_test();

Function to test whether the SM3 algorithm is correct. The function returns 0 for error and other values for correct.

