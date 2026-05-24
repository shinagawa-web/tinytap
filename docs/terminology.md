# Terminology

These terms appear throughout the docs, the code, and the issue tracker. They are deliberately **process-relative** — "from whose point of view?" matters.

| Term | Meaning |
|---|---|
| **Outgoing syscall** | A syscall that writes data *out of* a process address space: `write`, `sendto`, `sendmsg`, `writev`. The user buffer is already populated at `sys_enter`, so the payload can be sampled on entry. |
| **Incoming syscall** | A syscall that reads data *into* a process address space: `read`, `recvfrom`, `recvmsg`, `readv`. The user buffer is empty at `sys_enter` — the kernel fills it during the syscall, so the payload is only observable at `sys_exit` (with the return value telling us how much was actually filled). |
| **send-side** / **receive-side** | Synonyms for outgoing / incoming, common in libbpf and Pixie writing. Acceptable once a paragraph has already grounded the direction; avoid as the *first* mention because they sound like they refer to the protocol direction (request vs response) when they actually refer to the syscall family. |

## Protocol mapping (HTTP)

`tinytap` is process-oriented, not protocol-aware. The same syscall carries the **request** on one side and the **response** on the other depending on who is calling it:

| Process | Outgoing payload = | Incoming payload = |
|---|---|---|
| HTTP server (e.g. `python3 -m http.server`) | response | request |
| HTTP client (e.g. `curl`) | request | response |

So "the HTTP response" is *not* a synonym for "outgoing payload" — it depends which process is being observed. When protocol direction matters, write it out: "the HTTP response (server's outgoing payload)" rather than just "the send-side payload".
