
#include <aes_test.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>


int main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(should_encrypt_aes_ecb_128_correctly),
		cmocka_unit_test(should_encrypt_aes_cbc_128_correctly),
		cmocka_unit_test(should_encrypt_aes_ctr_128_correctly),
		cmocka_unit_test(should_encrypt_aes_cfb_1_correctly)
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
