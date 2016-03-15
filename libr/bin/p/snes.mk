OBJ_SNES=bin_snes.o

STATIC_OBJ+=${OBJ_SNES}
TARGET_SNES=bin_snes.${EXT_SO}

ALL_TARGETS+=${TARGET_SNES}

${TARGET_SNES}: ${OBJ_SNES}
	${CC} $(call libname,bin_snes) -shared ${CFLAGS} \
		-o ${TARGET_SNES} ${OBJ_SNES} $(LINK) $(LDFLAGS)
