# **************************************************************************** #
#                                                                              #
#                                                         :::      ::::::::    #
#    Makefile                                           :+:      :+:    :+:    #
#                                                     +:+ +:+         +:+      #
#    By: alagroy- <alagroy-@student.42.fr>          +#+  +:+       +#+         #
#                                                 +#+#+#+#+#+   +#+            #
#    Created: 2022/02/09 14:49:38 by alagroy-          #+#    #+#              #
#    Updated: 2022/06/28 00:14:57 by alagroy-         ###   ########.fr        #
#                                                                              #
# **************************************************************************** #

NAME = infector

SRCS = infector.s
OBJDIR = ./.objs/
SRCDIR = ./srcs/
OBJ_FILES = $(SRCS:.s=.o)
OBJS = $(addprefix $(OBJDIR), $(OBJ_FILES))
INCLUDES = ./srcs/defines.s

all : $(OBJDIR) $(NAME)

$(NAME): $(OBJS) 
	ld --omagic -e _start -o $@ $<
	printf "\n\033[0;32m[$(NAME)] Linking [OK]\n\033[0;0m"

$(OBJDIR)%.o: $(SRCDIR)%.s $(INCLUDES) Makefile 
	nasm -i $(SRCDIR) -f elf64 -o $@ $<
	printf "\033[0;32m[$(NAME)] Compilation [$<]                 \r\033[0m"

$(OBJDIR):
	mkdir -p $@

test: all sample
	mkdir -p /tmp/test
	mkdir -p /tmp/test2
	touch /tmp/test/test1
	touch /tmp/test/test2
	touch /tmp/test/test3
	cp sample /tmp/test2/sample
	cp /bin/ls /tmp/test/ls

sample: sample.c
	gcc -Wall -Werror -Wextra -o $@ $<

clean:
	$(RM) -Rf $(OBJDIR)
	printf "\033[0;31m[$(NAME)] Clean [OK]\n"

fclean: clean
	$(RM) $(NAME)
	printf "\033[0;31m[$(NAME)] Fclean [OK]\n"

re: fclean all

.PHONY: clean re fclean all test
.SILENT:
