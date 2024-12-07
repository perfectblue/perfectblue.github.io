---

title: "SpongeBox - Bringing Linux Logical Vulnerabilities Back To Life - BlueWater CTF 2024"
layout: post
description: "A walkthrough of "SpongeBox" - a Linux-based sandbox escape challenge from Blue Water CTF 2024" 
date: 2024-12-07 13:37:31

---
*Author: Jonathan Jacobi ([@j0nathanj](https://x.com/j0nathanj))*.

SpongeBox was a Linux-based sandbox escape challenge for Blue Water CTF 2024. The original motivation for this challenge was actually based on an old Linux kernel vulnerability and some interesting behaviors, which ended up as a really nice CTF challenge!

There is a `/flag` file that is readable only by root. The challenge runs as root initially.

The relevant files for the challenge can be found [here](https://github.com/BlueWaterCTF/bwctf-2024-challs/tree/main/pwn/SpongeBox) (SpongeBob.tar.gz was handed out).

## The Challenge 
The layout of the challenge is pretty simple: a server (written in C) that listens for connections and supports 3 possible commands:

1. **Creating** a sandbox and running an ELF binary.

2. **Connecting to a sandbox:** The Sandboxee should set `stdin`/`stdout` as FDs that are going to be used by the Sandboxer, in a way that the Sandboxee can `read()` from `stdin` data that the Sandboxer sent, and `write()` to `stdout` data that the Sandboxer will receive.

3. **Communicating with the sandbox**: This will `write()` into the `stdin` FD of the Sandboxee to allow this data to be read inside the Sandbox. It will also `read()` data from the `stdout` that was set up for the Sandboxee and send back the result.

This whole behavior essentially mimics the ability to set up a sandbox, run a binary in it, communicate with it, and get the results.


### 1. `CMD_CREATE` - Creating a Sandbox 🆕
This function essentially to create a new sandboxed process, and receives the contents of an ELF file that will be executed from within the sandbox.

The sandboxer creates a new sandboxee process, with all new namespaces. The sandbox creation is done by a "weak" user (non-root).

The sandbox creation also creates a `socketpair()` and shares it with the sandboxee, to be able to sync with it. Specifically, to allow the sandboxer to FIRST map the uid & gid of the new user namespace, before the sandboxee tries to `setuid()`.

```c
int create_sandbox(sandbox_args_t *args) {
    // ... 
    
    // Create a socketpair for synchronization
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sync_socket) == -1) {
        perror("socketpair");
        munmap(stack, STACK_SIZE);
        return -1;
    }
    // Drop privileges before creating the sandboxee
    drop_privileges();

    child_pid = clone(run_sandbox, stackTop,  CLONE_NEWPID | CLONE_NEWNET | CLONE_NEWUTS |CLONE_NEWCGROUP | CLONE_NEWIPC | CLONE_NEWNS | CLONE_NEWUSER | SIGCHLD, args);
```

The call to `drop_privileges()` essentially means that the owning user of the new user namespace created, is a non-root one.

```c
void drop_privileges(void) {
    if (setegid(DEFAULT_GID) != 0) {
        perror("setegid failed in drop_privileges");
        exit(-1);
    }

    if (seteuid(DEFAULT_UID) != 0) {
        perror("seteuid failed in drop_privileges");
        exit(-1);
    }
}
```

And, the synchronization of with the child for the mapping purposes, as can be seen:
```c
int create_sandbox(sandbox_args_t *args) {
    // ... 
    // ...
    child_pid = clone(run_sandbox, stackTop,  CLONE_NEWPID | CLONE_NEWNET | CLONE_NEWUTS |CLONE_NEWCGROUP | CLONE_NEWIPC | CLONE_NEWNS | CLONE_NEWUSER | SIGCHLD, args);

    // Gain capabilities to continue the sandboxer
    gain_privileges();
    // ...

    // Parent process: set up UID/GID mappings for the child
    deny_setgroups(child_pid);
    setup_idmaps(child_pid, args->uid, args->gid);

    // Signal the child that UID/GID mappings are set up
    if (write(sync_socket[0], "x", 1) != 1) {
        perror("Failed to write to sync socket");
    }
    // ...
}
```

An interesting thing to note here, is that both the `uid` and the `gid` that used as the inner `uid` and `gid` inside the sandbox - are strings (yes, verified properly to be all digits...) controlled remotely. This in itself is not a security issue, as those are the ids inside the sandbox - and they can be arbitrary values.

#### Sandbox creation - `run_sandbox()`
This function is the entry point for the sandboxee. It essentially sets up the sandbox, and then `execveat()`-s the ELF memfd created.
```c
void run_sandbox(sandbox_args_t *args) {
    // Close the parent's end of the sync socket
    close(sync_socket[0]);

    PCHECK(setup_sandbox(args->uid, args->gid) == 0, "setup_sandbox failed");
    // Close the child's end of the sync socket
    close(sync_socket[1]);

    execveat(args->fd, "", NULL, NULL, AT_EMPTY_PATH);
    PCHECK(false, "execveat failed");
}
```

The `setup_sandbox()` logic is also pretty simple. Simply calls `setresgid()` and `setresuid()` for the inner-uids, after it receives the signal from the sandboxer that the uid and the gid are mapped. 

Let's take a look at it:
```c
static int setup_sandbox(char *uid, char *gid) {
    char sync_char = '\x00';
    uid_t uid_num  = 0;
    gid_t gid_num = 0;

    // Wait for parent to set up UID/GID mappings and setgroup configuration
    if (read(sync_socket[1], &sync_char, 1) != 1) {
        FAIL("Failed to read from sync socket");
    }

    uid_num = atoi(uid);
    gid_num = atoi(gid);

    // Set the newly mapped user and group ids
    become_user_group(uid_num, gid_num);
    return 0;
}
```

And, the `become_user_group`, also pretty simple:
```c
void become_user_group(uid_t uid, gid_t gid) {
    // Switch to the newly mapped user and group
    setresgid(gid, gid, gid);
    setresuid(uid, uid, uid);
}
```

#### 💡 **Primitive #1**: Lack of return value check of `setresuid()` and `setresgid()` 
Those 2 function calls do not check any return values. Meaning if the set does not work, well.. nothing too special will happen. 

It's not very interesting on its own here, but let's keep that in the back of our minds!

#### Sandbox creation - `setup_idmaps()`
The other interesting function to examine is the `setup_idmaps()` function, responsible for mapping the `uid` and `gid` provided, into the newly created user namespace.

The supplied `uid` and `gid` parameters are controlled remotely, and those are the IDs inside the sandbox.

```c
void setup_idmaps(pid_t pid, char *uid, char *gid) {
    int uid_map_fd = -1, gid_map_fd = -1; 
    char *uid_map = NULL, *gid_map = NULL;
    char *uid_map_path = NULL, *gid_map_path = NULL;

    // Open the uid_map file
    asprintf(&uid_map_path, "/proc/%d/uid_map", pid);
    uid_map_fd = open(uid_map_path, O_WRONLY);

    // Write the mapping
    asprintf(&uid_map, "%s %d 1", uid, DEFAULT_UID);
    write(uid_map_fd, uid_map, strlen(uid_map) + 1);

    // Open the gid_map file
    asprintf(&gid_map_path, "/proc/%d/gid_map", pid);
    gid_map_fd = open(gid_map_path, O_WRONLY);
    
    // Write the mapping
    asprintf(&gid_map, "%s %d 1", gid, DEFAULT_GID);
    write(gid_map_fd, gid_map, strlen(gid_map) + 1);
}
```

#### 💡 Primitives #2 + #3: UID/GID Maps setups trickeries
Clearly there are a few more interesting things here as well:
1. 💡 **Primitive #2**: No return value checks for writing to the uid and gid maps.
2. 💡 **Primitive #3**: The `uid_map` and `gid_map` fds are left open and leaked. In most cases this is not useful, as writing to `uid_map` and `gid_map` is possible only once (🤔)

Given those 2 primitives, we can only wonder - can we get the `write()` to the `uid_map` to fail, and somehow leak an FD to a yet-to-be-written `uid_map`? Why does this even help us...?

#### 🛑 A Linux Kernel History Lesson!
A very intereting observation about the `uid_map` is that different users can write different contents to the file, but everyone can open it.

This is somewhat unusual, as we're used to either being able to write to a file, or not - based on the file's permissions. We're less used to permission checks conducted upon `write()`.

The case of `uid_map` is that there IS a check upon `write()`, and it allows different things for different writers.

An interesting question comes up - what if we `open()` the `uid_map` and inherit it as an `stdout`/`stderr` FD to a privileged process? For example - by `execve()`-ing a suid binary?

Specifically, we can exec `sudo` and also change `argv[0]` to be an arbitrary content, and if we fail with the password we can cause a partially controlled `write()` to that FD, by a privileged process! 
* It usually writes `sudo: 3 incorrect password attempts` or something like that. `sudo` is actually `argv[0]` - so if we change that, we have a partially controlled `write()`.

We can make that a more precise write, by coming up with creative primitives like `ulimit()`-s. But you get the idea...

So is that going to work???

#### Almost... but more permission checks 😔
Turns out that for a short while, this was an actual [vulnerability](https://github.com/torvalds/linux/commit/6708075f104c3c9b04b23336bb0366ca30c3931b)!

The way the solved it is by ALSO recording the permissions of the OPENER of the file - and during the `write()` there is a check that verifies that both the opener and the writer have the write permissions (`CAP_SYS_ADMIN` in the target user namespace).

#### ⏩ Going back to the challenge: Leaking the `uid_map` fd
So if you recall, we were wondering if it would even be interesting to leak the `uid_map` FD - and we just found out that IT IS INTERESTING, and that is because the OPENER of the `uid_map` in `setup_idmaps()` is a privileged (root) process!

The next logical question is... can we leak the `uid_map` fd?

#### 💡 **Primitive #4**: Leaking the FD!
Well, we need to get the `write()` to fail, as writing to the `uid_map` is allowed only once (that makes sense too, the kernel devs don't want race conditions around ids...).

Let's take a look at how the `write()` handler for `uid_map` is implemented in the Linux Kernel source code.

This is actually implemented inside `/kernel/user_namespace.c` under `map_write()`:
```c
static ssize_t map_write(struct file *file, const char __user *buf,
			 size_t count, loff_t *ppos,
			 int cap_setid,
			 struct uid_gid_map *map,
			 struct uid_gid_map *parent_map)
{
    // ...
	char *kbuf, *pos, *next_line;

	/* Only allow < page size writes at the beginning of the file */
	if ((*ppos != 0) || (count >= PAGE_SIZE))
		return -EINVAL;

    // ...
    /* Only allow one successful write to the map */
	if (map->nr_extents != 0)
		goto out;
```

Straight off the bat we notice the check that allows for only 1 successful write to `uid_map`.

We also immediately see a **FAIL FAST** check in the beginning - that requires:
1. The `write()` to not be `lseek()`-ed before (the check with `ppos`).
2. The amount of bytes that are going to be written to the `uid_map` to be less than `PAGE_SIZE` (4096).

Well, we can't cause an `lseek()` - but... remember we remotely control the `uid` (as a string!!!) of the inner user namespace? 

#### 💡 **Primitive #5**: Leaking a high-permission `open()` & no `write()` FD to a `uid_map`

Combining those points together, we can come up with the following insight!

The handler for `CMD_CREATE` indeed checks the `uid` is a digit-only string, but it can also be up to `4096` (`MAX_STRING_SIZE`) bytes long, which means that together as a whole -- the string written to the `uid_map` is longer than 4096 bytes, and we can make `write()` fail! 

This is how the handler looks like in `main()`:
```c
                if ((bytes_read != sizeof(uid_size)) || 
                    (uid_size >= MAX_STRING_SIZE)) {
                    send_error(1, "Failed to receive UID size");
                    break;
                }

                bytes_read = read(0, uid, uid_size);
                if (bytes_read != uid_size) {
                    send_error(1, "Failed to receive UID");
                    break;
                }
                uid[uid_size] = '\0';  // Ensure null-termination

                // Verify this is an actual number
                if (!is_valid_number(uid)) {
                    send_error(1, "Invalid UID");
                    break;
                }
```                

Can clearly be seen that we can pass up to `MAX_STRING_SIZE` digits, which is more than enough!

### 📋 Primitives so far!
Using primitive #2, #3 and #4 - we can finally achieve #5, which is:
Having a leaked `uid_map` FD in the Sandboxer process, that is `open()`-ed by a privileged process, and not `write()`-ten into.

Also utilizing primtiive #1 - it means that the `setresuid()` and `setresgid()` that happen in the SANBOXED process, that exists there in order to become the desired UID/GID inside the sandbox, will fail. 

It will fail because the mapping did not ACTUALLY take place, so changing to an inner UID will not work as it is not mapped. BUT this is not going to make any difference as the retun value is ignored, as seen in primitive #1!

This is enough from `CMD_CREATE`, but we definitely found some very interesting behaviors!

### 2. `CMD_CONNECT`: Connecting to the sandbox 🔗
This logic is very simple. Simply grabbing the fd = 0 and fd = 1 of a sandboxee (based on a sandbox id), using `pidfd_getfd()` - and saving it in the struct that represents the sandbox. 

```c
int connect_sandbox(sandbox_t *sandbox) {
    // ...
    // Open a file descriptor to the sandbox process
    pidfd = syscall(SYS_pidfd_open, sandbox->pid, 0);
    if (pidfd == -1) {
        printf("pidfd_open failed\n");
        goto cleanup;
    }

    // Get file descriptor (stdin) from the sandbox process
    stdin_fd = syscall(SYS_pidfd_getfd, pidfd, STDIN, 0);
    if (stdin_fd == -1) {
        printf("pidfd_getfd failed for stdin with err %s\n", strerror(errno));
        goto cleanup;
    }

    // Get file descriptor 1 (stdout) from the sandbox process
    stdout_fd = syscall(SYS_pidfd_getfd, pidfd, STDOUT, 0);
    if (stdout_fd == -1) {
        printf("pidfd_getfd failed for stdout with err %s\n", strerror(errno));
        goto cleanup;
    }

    sandbox->stdin_fd = stdin_fd;
    sandbox->stdout_fd = stdout_fd;
    // ... 
```
Pretty simple stuff!

#### 💡 **Primitive #6**: Actually receiving a leaked `uid_map` fd to a Sandboxee
Once we leak an FD in the Sandboxer, we can create yet another Sandbox, and it will be spawned with a leaked `uid_map` fd as we descrbied above!

### 3. `CMD_COMMUNICATE` - Communicating with the sandbox 💬 
This logic is also very trivial. Simply writing to the `stdin` that was grabbed in the `CMD_CONNECT` phase, and reading from `stdout` (yes, those are the right operations -- the `stdout` is actually where the sanboxee writes, so we're reading from it. And the other way around with `stdin`).

#### 💡 **Primitive #7**: Writing to the `uid_map` from a privileged process!
Recall that we managed to leak the `uid_map` fd to the sandboxee. Also, that same FD has not been written into, and it is `open()`-ed by root.

Meaning, we just need to write to it from a privileged process, as seen before in the kernel checks.

Given the fact that the sandboxer can "steal" `stdin` and `stdout` - the Sandboxcee can `dup2()` the leaked FD into the FD that the Sandboxer is going to steal and write into (`stdin`, fd == 0).
This KEEPS the permissions of the opener to be the original opener, which is root. And it workws!

Now the only thing that's left is writing WHATEVER WE WANT into the `uid_map`, and that's going to be permitted!

## Chaining it all together! 🔗 💣
Summarizing it all together, the attack would look like this:
1. Create the first sandboxee + make the UID be `4095 * '0'` which will cause the `write()` to the `uid_map` to fail, and leak the FD in the sandboxer.
2. The first sandboxee will execute our custom binary that will `sleep()` a bit :)
3. Now create a second sandboxee. Make it legit.
4. The second sandboxee has the `uid_map` of the first sandboxee mapped into it, as fd == 6 (leaked).
5. In the second sandboxee, `dup2()` the fd == 6 into fd == 0 (`stdin`).
6. Call `CMD_CONNECT` with the second sandboxee, which will grab the `uid_map` fd into the sandboxer.
7. Call `CMD_COMMUNICATE` with the second sandboxee, and write `'0 0 1'` to it, which will map the real UID == 0 into UID == 0 inside the FIRST SANDBOXEE.
8. Inside the first sandboxee, we're privileged and we can `setuid(0)` which will give us a REAL ROOT PRIVILEGE. 
9. From the first sandboxee, just read the flag file, and using `CMD_COMMUNICATE` leak it outside.
10. Profit :)

## Summary 🏁
I really enjoyed writing this challenge, especially as it involved chaining multiple logical issues together into something that is not so trivial to think of.

I hope you enjoyed the walkthrough, and feel free to reach out to me on X [@j0nathanj](https://x.com/j0nathanj)!

