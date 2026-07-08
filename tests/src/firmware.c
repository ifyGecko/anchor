/* Common test firmware source used across all architectures.
 *
 * Provides strings, function-pointer tables, and simple code so that
 * anchor.py has a rich signal (pointer-to-string, self-referential
 * pointers) to work with. Not intended to actually run - only to be
 * linked at a known base address and dumped as a raw binary. */

#include <stdint.h>

const char s1[]  = "anchor_test_alpha_bravo_charlie";
const char s2[]  = "anchor_test_delta_echo_foxtrot_golf";
const char s3[]  = "anchor_test_hotel_india_juliet_kilo";
const char s4[]  = "anchor_test_lima_mike_november_oscar";
const char s5[]  = "anchor_test_papa_quebec_romeo_sierra";
const char s6[]  = "anchor_test_tango_uniform_victor";
const char s7[]  = "anchor_test_whiskey_xray_yankee_zulu";
const char s8[]  = "anchor_test_the_quick_brown_fox_jumps";
const char s9[]  = "anchor_test_lorem_ipsum_dolor_sit_amet";
const char s10[] = "anchor_test_consectetur_adipiscing_elit";

const char * const string_table[] = {
    s1, s2, s3, s4, s5, s6, s7, s8, s9, s10
};

int compute_a(int x) { return x * 2 + 1; }
int compute_b(int x) { return compute_a(x) + 3; }
int compute_c(int x) { return compute_b(x) * compute_a(x); }
int compute_d(int x) { return compute_c(x) - compute_b(x); }
int compute_e(int x) { return compute_d(x) + compute_a(x) * 5; }
int compute_f(int x) { return compute_e(x) * 2 - compute_c(x); }
int compute_g(int x) { return compute_f(x) + compute_d(x) - 7; }
int compute_h(int x) { return compute_g(x) ^ compute_e(x); }

typedef int (*fn_t)(int);
const fn_t fn_table[] = {
    compute_a, compute_b, compute_c, compute_d,
    compute_e, compute_f, compute_g, compute_h
};

volatile int sink;

int main_(void) {
    int r = 0;
    for (int i = 0; i < 32; i++) {
        for (int j = 0; j < 8; j++) {
            r += fn_table[j](i);
        }
        for (int j = 0; j < 10; j++) {
            const char *p = string_table[j];
            r += (int)(uintptr_t)p;
        }
    }
    sink = r;
    return r;
}

int _start(void) {
    return main_();
}
