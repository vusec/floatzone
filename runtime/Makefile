all: libwrap.so libcmp.so

libwrap.so: wrap.c
	${DEFAULT_C} -fPIC -shared -g -O2 -o libwrap.so wrap.c -lm -ldl -I${FLOATZONE_XED_INC} -I${FLOATZONE_XED_INC_OBJ} -D LIBXED_SO='"${FLOATZONE_XED_LIB_SO}"' -Wl,-z,now

libcmp.so: cmp.c
	${DEFAULT_C} -fPIC -shared -g -O2 -o libcmp.so cmp.c -lm -ldl

clean:
	rm -f *.so
