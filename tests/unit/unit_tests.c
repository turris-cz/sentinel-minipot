#include <check.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>

void suite_check_serv_data(SRunner*);
void suite_skip_sel_bytes(SRunner *);

int main(void) {
	SRunner *runner = srunner_create(NULL);
	suite_check_serv_data(runner);
	suite_skip_sel_bytes(runner);

	char *test_output_tap = getenv("TEST_OUTPUT_TAP");
	if (test_output_tap && *test_output_tap != '\0')
		srunner_set_tap(runner, test_output_tap);
	char *test_output_xml = getenv("TEST_OUTPUT_XML");
	if (test_output_xml && *test_output_xml != '\0')
		srunner_set_xml(runner, test_output_xml);
	if (getenv("VALGRIND")) // Do not fork with valgrind
		srunner_set_fork_status(runner, CK_NOFORK);

	srunner_run_all(runner, CK_NORMAL);
	bool failed = (bool)srunner_ntests_failed(runner);

	srunner_free(runner);
	return failed;
}
