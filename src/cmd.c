// SPDX-License-Identifier: BSD-3-Clause

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "cmd.h"
#include "utils.h"

#define READ		0
#define WRITE		1

/* Saves the std file descriptors of a process */
static int save_fdts(int *stdin, int *stdout, int *stderr)
{
	*stdin = dup(STDIN_FILENO);
	if (*stdin < 0)
		return *stdin;

	*stdout = dup(STDOUT_FILENO);
	if (*stdout < 0) {
		close(*stdin);
		return *stdout;
	}

	*stderr = dup(STDERR_FILENO);
	if (*stderr < 0) {
		close(*stdin);
		close(*stdout);
		return *stderr;
	}

	return 0;
}

/* Restore std file descriptors to given values */
static int restore_fdts(int stdin, int stdout, int stderr)
{
	dup2(stdin, STDIN_FILENO);
	dup2(stdout, STDOUT_FILENO);
	dup2(stderr, STDERR_FILENO);

	close(stdin);
	close(stdout);
	close(stderr);

	return 0;
}

/* Returns the number of args of a command */
static int argcount(simple_command_t *s)
{
	int argc = 0;
	word_t *params = s->params;

	while (params != NULL) {
		params = params->next_word;
		argc++;
	}

	return argc;
}

/* Redirect input / output / error
 * On succesfull redirection returns true
 * If no redirection was done returns false
 * Returns a negative integer on error
 */
static int redirect(simple_command_t *s)
{
	int fd, redirected = false;

	/* Input redirection */
	if (s->in) {
		char *in_file = get_word(s->in);

		fd = open(in_file, O_RDONLY);

		if (fd < 0) {
			free(in_file);

			return fd;
		}

		redirected = true;

		dup2(fd, STDIN_FILENO);
		free(in_file);
		close(fd);
	}

	/* Output redirection */
	if (s->out) {
		char *out_file = get_word(s->out);

		if (s->io_flags & IO_OUT_APPEND)
			fd = open(out_file, O_WRONLY | O_CREAT | O_APPEND, 0644);
		else
			fd = open(out_file, O_WRONLY | O_CREAT | O_TRUNC, 0644);

		if (fd < 0) {
			free(out_file);

			return fd;
		}

		redirected = true;

		/* Output and Error redirected to same file */
		if (s->err) {
			char *err_file = get_word(s->err);

			if (!strcmp(out_file, err_file)) {
				dup2(fd, STDERR_FILENO);
				dup2(fd, STDOUT_FILENO);

				free(out_file);
				free(err_file);
				close(fd);

				return redirected;
			}

			free(err_file);
		}

		dup2(fd, STDOUT_FILENO);
		free(out_file);
		close(fd);
	}

	if (s->err) {
		char *err_file = get_word(s->err);

		if (s->io_flags & IO_ERR_APPEND)
			fd = open(err_file, O_WRONLY | O_CREAT | O_APPEND, 0644);
		else
			fd = open(err_file, O_WRONLY | O_CREAT | O_TRUNC, 0644);

		if (fd < 0) {
			free(err_file);

			return fd;
		}

		redirected = true;

		dup2(fd, STDERR_FILENO);
		free(err_file);
		close(fd);
	}

	return redirected;
}

/**
 * Internal change-directory command.
 */
static bool shell_cd(word_t *dir)
{
	/* TODO: Execute cd. */
	int rc;
	char *dir_name = get_word(dir);

	rc = chdir(dir_name);
	free(dir_name);

	return rc;
}

/**
 * Internal exit/quit command.
 */
static int shell_exit(void)
{
	/* TODO: Execute exit/quit. */

	return SHELL_EXIT; /* TODO: Replace with actual exit code. */
}

/**
 * Parse a simple command (internal, environment variable assignment,
 * external command).
 */
static int parse_simple(simple_command_t *s, int level, command_t *father)
{
	/* TODO: Sanity checks. */
	if (!s || level < 0)
		return -1;

	char *cmd = get_word(s->verb);

	/* TODO: If builtin command, execute the command. */
	if (!strcmp(cmd, "cd")) {
		if (argcount(s) != 1) {
			free(cmd);
			return -1;
		}

		free(cmd);

		int rc, stdin, stdout, stderr;

		rc = save_fdts(&stdin, &stdout, &stderr);
		if (rc < 0)
			return -1;

		redirect(s);

		rc = shell_cd(s->params);

		restore_fdts(stdin, stdout, stderr);

		return rc;
	}

	if (!strcmp(cmd, "pwd")) {
		char *cwd = getcwd(NULL, 0);

		if (cwd == NULL) {
			free(cmd);
			return -1;
		}

		int rc, stdin, stdout, stderr;

		rc = save_fdts(&stdin, &stdout, &stderr);
		if (rc < 0)
			return -1;

		redirect(s);

		puts(cwd);
		free(cwd);

		restore_fdts(stdin, stdout, stderr);

		free(cmd);

		return 0;
	}

	if (!strcmp(cmd, "quit") || !strcmp(cmd, "exit")) {
		free(cmd);

		return shell_exit();
	}

	/* TODO: If variable assignment, execute the assignment and return
	 * the exit status.
	 */
	char *value = strchr(cmd, '=');

	if (value && cmd[0] != '=') {
		int rc = setenv(s->verb->string, value + 1, 1);

		free(cmd);

		return rc;
	}

	/* TODO: If external command:
	 *   1. Fork new process
	 *     2c. Perform redirections in child
	 *     3c. Load executable in child
	 *   2. Wait for child
	 *   3. Return exit status
	 */

	pid_t pid;
	char **args;
	int size, wstatus, rc;

	pid = fork();

	switch (pid) {
	case -1:
		DIE(1, "fork");
		break;

	case 0:
		rc = redirect(s);
		DIE(rc < 0, "redirect");
		args = get_argv(s, &size);

		rc = execvp(args[0], args);

		fprintf(stderr, "Execution failed for '%s'\n", cmd);

		exit(rc);
		break;

	default:
		wait(&wstatus);
		free(cmd);
		break;
	}

	return WEXITSTATUS(wstatus); /* TODO: Replace with actual exit status. */
}

/**
 * Process two commands in parallel, by creating two children.
 */
static bool run_in_parallel(command_t *cmd1, command_t *cmd2, int level,
		command_t *father)
{
	/* TODO: Execute cmd1 and cmd2 simultaneously. */
	pid_t pid, pid1;
	int rc, rc1, wstatus, wstatus1;

	pid = fork();

	switch (pid) {
	case -1:
		DIE(1, "fork");
		break;

	case 0:
		rc = parse_command(cmd1, level, father);

		exit(rc);
		break;

	default:
		pid1 = fork();

		switch (pid1) {
		case -1:
			DIE(1, "fork");
			break;

		case 0:
			rc1 = parse_command(cmd2, level, father);

			exit(rc1);
			break;

		default:
			waitpid(pid1, &wstatus1, 0);
			break;
		}

		waitpid(pid, &wstatus, 0);
		break;
	}

	return WEXITSTATUS(wstatus1) | WEXITSTATUS(wstatus1); /* TODO: Replace with actual exit status. */
}

/**
 * Run commands by creating an anonymous pipe (cmd1 | cmd2).
 */
static bool run_on_pipe(command_t *cmd1, command_t *cmd2, int level,
		command_t *father)
{
	/* TODO: Redirect the output of cmd1 to the input of cmd2. */
	pid_t pid, pid1;
	int rc, rc1, wstatus, wstatus1, pipe_fd[2];

	rc = pipe(pipe_fd);

	if (rc < 0)
		return rc;

	pid = fork();

	switch (pid) {
	case -1:
		DIE(1, "fork");
		break;

	/* Left child writes to pipe */
	case 0:
		close(pipe_fd[0]);

		dup2(pipe_fd[1], STDOUT_FILENO);
		close(pipe_fd[1]);

		rc = parse_command(cmd1, level, father);

		exit(rc);
		break;

	default:
		pid1 = fork();

		switch (pid1) {
		case -1:
			DIE(1, "fork");
			break;

		/* Right child reads from pipe */
		case 0:
			close(pipe_fd[1]);

			dup2(pipe_fd[0], STDIN_FILENO);
			close(pipe_fd[0]);

			rc1 = parse_command(cmd2, level, father);

			exit(rc1);
			break;

		default:
			close(pipe_fd[0]);
			close(pipe_fd[1]);
			waitpid(pid1, &wstatus1, 0);
			break;
		}

		waitpid(pid, &wstatus, 0);
		break;
	}

	return WEXITSTATUS(wstatus1) | WEXITSTATUS(wstatus1);
}

/**
 * Parse and execute a command.
 */
int parse_command(command_t *c, int level, command_t *father)
{
	/* TODO: sanity checks */
	int rc, rc1;

	if (c->op == OP_NONE) {
		/* TODO: Execute a simple command. */
		rc = parse_simple(c->scmd, level, father);

		return rc; /* TODO: Replace with actual exit code of command. */
	}

	switch (c->op) {
	case OP_SEQUENTIAL:
		/* TODO: Execute the commands one after the other. */
		rc1 = parse_command(c->cmd1, level + 1, c);
		rc = parse_command(c->cmd2, level + 1, c);
		rc |= rc1;

		break;

	case OP_PARALLEL:
		/* TODO: Execute the commands simultaneously. */
		rc = run_in_parallel(c->cmd1, c->cmd2, level + 1, c);

		break;

	case OP_CONDITIONAL_NZERO:
		/* TODO: Execute the second command only if the first one
		 * returns non zero.
		 */
		rc = parse_command(c->cmd1, level + 1, c);

		if (rc)
			rc = parse_command(c->cmd2, level + 1, c);

		break;

	case OP_CONDITIONAL_ZERO:
		/* TODO: Execute the second command only if the first one
		 * returns zero.
		 */
		rc = parse_command(c->cmd1, level + 1, c);

		if (!rc)
			rc = parse_command(c->cmd2, level + 1, c);

		break;

	case OP_PIPE:
		/* TODO: Redirect the output of the first command to the
		 * input of the second.
		 */
		rc = run_on_pipe(c->cmd1, c->cmd2, level + 1, c);

		break;

	default:
		return SHELL_EXIT;
	}

	return rc; /* TODO: Replace with actual exit code of command. */
}
