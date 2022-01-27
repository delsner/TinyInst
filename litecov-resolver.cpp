#include <stdio.h>

int main(int argc, char** argv)
{
    if (argc < 2) {
        printf("Usage:\n");
        return 1;
    }

    // 1. collect all coverage files in directory with .cov extension
    // 2. Create empty coverage report
    // 3. Iterate over coverage files
    // 4. Lookup symbol and store (test_id, module_name, offset, file, line) into coverage report
    // 5. Write coverage report to CSV file

    return 0;
}