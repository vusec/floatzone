CFLAGS = -O2 -g -Wl,-z,now 


all: buggy buggy_asan buggy_floatzone

buggy:
	${DEFAULT_C} buggy.c -o buggy ${CFLAGS}

buggy_asan:
	${DEFAULT_C} buggy.c -o buggy_asan ${CFLAGS} -fsanitize=address

buggy_floatzone:
	${FLOATZONE_C} buggy.c -o buggy_floatzone_run_base ${CFLAGS}

clean:
	rm -f buggy buggy_asan buggy_floatzone
