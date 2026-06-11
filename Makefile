## EPITECH PROJECT, 2025
## Makefile
## File description:
## makefile for the my_ls project
##

CC    :=    clang

UTILS	=	utils.c

SRC_FILES =	binaryguard.c	\

BINAIRIES =	elf_file.c

JSON	=	write_json_report.c	\

TEST_SRC =	$(addprefix src/, $(SRC_FILES))		\

SRC    =	$(addprefix src/, $(SRC_FILES))		\
			$(addprefix src/, $(UTILS))			\
			$(addprefix src/, $(BINAIRIES))		\
			$(addprefix src/, $(JSON))			\
			$(addprefix src/, main.c)

TEST_OBJ =	$(TEST_SRC:.c=.o)

OBJ    =	$(SRC:.c=.o)


NAME    =    BinaryGuard

NAME_TEST    =    BinaryGuard_tests

CFLAGS = -iquote./includes/

all:    $(NAME)

$(NAME):    $(OBJ)
	$(CC) -o $(NAME) $(OBJ) $(CFLAGS)

make_to_test:    $(OBJ)
	$(CC) -o $(NAME_TEST) $(OBJ) $(CFLAGS)

unit_tests: fclean $(TEST_OBJ)
	$(CC) -o unit_tests $(TEST_OBJ) $(CFLAGS) --coverage -lcriterion

tests_run: unit_tests
	./unit_tests

clean_tests:
	$(RM) unit_tests
	$(RM) *.gcda && $(RM) *.gcno

clean:
	$(RM) $(OBJ)

fclean: clean
	$(RM) $(NAME)

re: fclean all

.PHONY: all make_to_test unit_tests tests_run clean clean_tests fclean re
