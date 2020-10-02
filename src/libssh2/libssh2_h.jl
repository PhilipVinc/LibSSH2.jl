# Julia wrapper for header: libssh2.h
# Automatically generated using Clang.jl


function libssh2_init(flags)
    ccall((:libssh2_init, libssh2), Cint, (Cint,), flags)
end

function libssh2_exit()
    ccall((:libssh2_exit, libssh2), Cvoid, ())
end

function libssh2_free(session, ptr)
    ccall((:libssh2_free, libssh2), Cvoid, (Ptr{LIBSSH2_SESSION}, Ptr{Cvoid}), session, ptr)
end

function libssh2_session_supported_algs(session, method_type, algs)
    ccall((:libssh2_session_supported_algs, libssh2), Cint, (Ptr{LIBSSH2_SESSION}, Cint, Ptr{Ptr{Cstring}}), session, method_type, algs)
end

function libssh2_session_init_ex(my_alloc, my_free, my_realloc, abstract)
    ccall((:libssh2_session_init_ex, libssh2), Ptr{LIBSSH2_SESSION}, (Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}), my_alloc, my_free, my_realloc, abstract)
end

function libssh2_session_abstract(session)
    ccall((:libssh2_session_abstract, libssh2), Ptr{Ptr{Cvoid}}, (Ptr{LIBSSH2_SESSION},), session)
end

function libssh2_session_callback_set(session, cbtype, callback)
    ccall((:libssh2_session_callback_set, libssh2), Ptr{Cvoid}, (Ptr{LIBSSH2_SESSION}, Cint, Ptr{Cvoid}), session, cbtype, callback)
end

function libssh2_session_banner_set(session, banner)
    ccall((:libssh2_session_banner_set, libssh2), Cint, (Ptr{LIBSSH2_SESSION}, Cstring), session, banner)
end

function libssh2_banner_set(session, banner)
    ccall((:libssh2_banner_set, libssh2), Cint, (Ptr{LIBSSH2_SESSION}, Cstring), session, banner)
end

function libssh2_session_startup(session, sock)
    ccall((:libssh2_session_startup, libssh2), Cint, (Ptr{LIBSSH2_SESSION}, Cint), session, sock)
end

function libssh2_session_handshake(session, sock)
    ccall((:libssh2_session_handshake, libssh2), Cint, (Ptr{LIBSSH2_SESSION}, libssh2_socket_t), session, sock)
end

function libssh2_session_disconnect_ex(session, reason, description, lang)
    ccall((:libssh2_session_disconnect_ex, libssh2), Cint, (Ptr{LIBSSH2_SESSION}, Cint, Cstring, Cstring), session, reason, description, lang)
end

function libssh2_session_free(session)
    ccall((:libssh2_session_free, libssh2), Cint, (Ptr{LIBSSH2_SESSION},), session)
end

function libssh2_hostkey_hash(session, hash_type)
    ccall((:libssh2_hostkey_hash, libssh2), Cstring, (Ptr{LIBSSH2_SESSION}, Cint), session, hash_type)
end

function libssh2_session_hostkey(session, len, type)
    ccall((:libssh2_session_hostkey, libssh2), Cstring, (Ptr{LIBSSH2_SESSION}, Ptr{Csize_t}, Ptr{Cint}), session, len, type)
end

function libssh2_session_method_pref(session, method_type, prefs)
    ccall((:libssh2_session_method_pref, libssh2), Cint, (Ptr{LIBSSH2_SESSION}, Cint, Cstring), session, method_type, prefs)
end

function libssh2_session_methods(session, method_type)
    ccall((:libssh2_session_methods, libssh2), Cstring, (Ptr{LIBSSH2_SESSION}, Cint), session, method_type)
end

function libssh2_session_last_error(session, errmsg, errmsg_len, want_buf)
    ccall((:libssh2_session_last_error, libssh2), Cint, (Ptr{LIBSSH2_SESSION}, Ptr{Cstring}, Ptr{Cint}, Cint), session, errmsg, errmsg_len, want_buf)
end

function libssh2_session_last_errno(session)
    ccall((:libssh2_session_last_errno, libssh2), Cint, (Ptr{LIBSSH2_SESSION},), session)
end

function libssh2_session_set_last_error(session, errcode, errmsg)
    ccall((:libssh2_session_set_last_error, libssh2), Cint, (Ptr{LIBSSH2_SESSION}, Cint, Cstring), session, errcode, errmsg)
end

function libssh2_session_block_directions(session)
    ccall((:libssh2_session_block_directions, libssh2), Cint, (Ptr{LIBSSH2_SESSION},), session)
end

function libssh2_session_flag(session, flag, value)
    ccall((:libssh2_session_flag, libssh2), Cint, (Ptr{LIBSSH2_SESSION}, Cint, Cint), session, flag, value)
end

function libssh2_session_banner_get(session)
    ccall((:libssh2_session_banner_get, libssh2), Cstring, (Ptr{LIBSSH2_SESSION},), session)
end

function libssh2_userauth_list(session, username, username_len)
    ccall((:libssh2_userauth_list, libssh2), Cstring, (Ptr{LIBSSH2_SESSION}, Cstring, UInt32), session, username, username_len)
end

function libssh2_userauth_authenticated(session)
    ccall((:libssh2_userauth_authenticated, libssh2), Cint, (Ptr{LIBSSH2_SESSION},), session)
end

function libssh2_userauth_password_ex(session, username, username_len, password, password_len, passwd_change_cb)
    ccall((:libssh2_userauth_password_ex, libssh2), Cint, (Ptr{LIBSSH2_SESSION}, Cstring, UInt32, Cstring, UInt32, Ptr{Cvoid}), session, username, username_len, password, password_len, passwd_change_cb)
end

function libssh2_userauth_publickey_fromfile_ex(session, username, username_len, publickey, privatekey, passphrase)
    ccall((:libssh2_userauth_publickey_fromfile_ex, libssh2), Cint, (Ptr{LIBSSH2_SESSION}, Cstring, UInt32, Cstring, Cstring, Cstring), session, username, username_len, publickey, privatekey, passphrase)
end

function libssh2_userauth_publickey(session, username, pubkeydata, pubkeydata_len, sign_callback, abstract)
    ccall((:libssh2_userauth_publickey, libssh2), Cint, (Ptr{LIBSSH2_SESSION}, Cstring, Ptr{Cuchar}, Csize_t, Ptr{Cvoid}, Ptr{Ptr{Cvoid}}), session, username, pubkeydata, pubkeydata_len, sign_callback, abstract)
end

function libssh2_userauth_hostbased_fromfile_ex(session, username, username_len, publickey, privatekey, passphrase, hostname, hostname_len, local_username, local_username_len)
    ccall((:libssh2_userauth_hostbased_fromfile_ex, libssh2), Cint, (Ptr{LIBSSH2_SESSION}, Cstring, UInt32, Cstring, Cstring, Cstring, Cstring, UInt32, Cstring, UInt32), session, username, username_len, publickey, privatekey, passphrase, hostname, hostname_len, local_username, local_username_len)
end

function libssh2_userauth_publickey_frommemory(session, username, username_len, publickeyfiledata, publickeyfiledata_len, privatekeyfiledata, privatekeyfiledata_len, passphrase)
    ccall((:libssh2_userauth_publickey_frommemory, libssh2), Cint, (Ptr{LIBSSH2_SESSION}, Cstring, Csize_t, Cstring, Csize_t, Cstring, Csize_t, Cstring), session, username, username_len, publickeyfiledata, publickeyfiledata_len, privatekeyfiledata, privatekeyfiledata_len, passphrase)
end

function libssh2_userauth_keyboard_interactive_ex(session, username, username_len, response_callback)
    ccall((:libssh2_userauth_keyboard_interactive_ex, libssh2), Cint, (Ptr{LIBSSH2_SESSION}, Cstring, UInt32, Ptr{Cvoid}), session, username, username_len, response_callback)
end

function libssh2_poll(fds, nfds, timeout)
    ccall((:libssh2_poll, libssh2), Cint, (Ptr{LIBSSH2_POLLFD}, UInt32, Clong), fds, nfds, timeout)
end

function libssh2_channel_open_ex(session, channel_type, channel_type_len, window_size, packet_size, message, message_len)
    ccall((:libssh2_channel_open_ex, libssh2), Ptr{LIBSSH2_CHANNEL}, (Ptr{LIBSSH2_SESSION}, Cstring, UInt32, UInt32, UInt32, Cstring, UInt32), session, channel_type, channel_type_len, window_size, packet_size, message, message_len)
end

function libssh2_channel_direct_tcpip_ex(session, host, port, shost, sport)
    ccall((:libssh2_channel_direct_tcpip_ex, libssh2), Ptr{LIBSSH2_CHANNEL}, (Ptr{LIBSSH2_SESSION}, Cstring, Cint, Cstring, Cint), session, host, port, shost, sport)
end

function libssh2_channel_forward_listen_ex(session, host, port, bound_port, queue_maxsize)
    ccall((:libssh2_channel_forward_listen_ex, libssh2), Ptr{LIBSSH2_LISTENER}, (Ptr{LIBSSH2_SESSION}, Cstring, Cint, Ptr{Cint}, Cint), session, host, port, bound_port, queue_maxsize)
end

function libssh2_channel_forward_cancel(listener)
    ccall((:libssh2_channel_forward_cancel, libssh2), Cint, (Ptr{LIBSSH2_LISTENER},), listener)
end

function libssh2_channel_forward_accept(listener)
    ccall((:libssh2_channel_forward_accept, libssh2), Ptr{LIBSSH2_CHANNEL}, (Ptr{LIBSSH2_LISTENER},), listener)
end

function libssh2_channel_setenv_ex(channel, varname, varname_len, value, value_len)
    ccall((:libssh2_channel_setenv_ex, libssh2), Cint, (Ptr{LIBSSH2_CHANNEL}, Cstring, UInt32, Cstring, UInt32), channel, varname, varname_len, value, value_len)
end

function libssh2_channel_request_pty_ex(channel, term, term_len, modes, modes_len, width, height, width_px, height_px)
    ccall((:libssh2_channel_request_pty_ex, libssh2), Cint, (Ptr{LIBSSH2_CHANNEL}, Cstring, UInt32, Cstring, UInt32, Cint, Cint, Cint, Cint), channel, term, term_len, modes, modes_len, width, height, width_px, height_px)
end

function libssh2_channel_request_pty_size_ex(channel, width, height, width_px, height_px)
    ccall((:libssh2_channel_request_pty_size_ex, libssh2), Cint, (Ptr{LIBSSH2_CHANNEL}, Cint, Cint, Cint, Cint), channel, width, height, width_px, height_px)
end

function libssh2_channel_x11_req_ex(channel, single_connection, auth_proto, auth_cookie, screen_number)
    ccall((:libssh2_channel_x11_req_ex, libssh2), Cint, (Ptr{LIBSSH2_CHANNEL}, Cint, Cstring, Cstring, Cint), channel, single_connection, auth_proto, auth_cookie, screen_number)
end

function libssh2_channel_process_startup(channel, request, request_len, message, message_len)
    ccall((:libssh2_channel_process_startup, libssh2), Cint, (Ptr{LIBSSH2_CHANNEL}, Cstring, UInt32, Cstring, UInt32), channel, request, request_len, message, message_len)
end

function libssh2_channel_read_ex(channel, stream_id, buf, buflen)
    ccall((:libssh2_channel_read_ex, libssh2), ssize_t, (Ptr{LIBSSH2_CHANNEL}, Cint, Cstring, Csize_t), channel, stream_id, buf, buflen)
end

function libssh2_poll_channel_read(channel, extended)
    ccall((:libssh2_poll_channel_read, libssh2), Cint, (Ptr{LIBSSH2_CHANNEL}, Cint), channel, extended)
end

function libssh2_channel_window_read_ex(channel, read_avail, window_size_initial)
    ccall((:libssh2_channel_window_read_ex, libssh2), Culong, (Ptr{LIBSSH2_CHANNEL}, Ptr{Culong}, Ptr{Culong}), channel, read_avail, window_size_initial)
end

function libssh2_channel_receive_window_adjust(channel, adjustment, force)
    ccall((:libssh2_channel_receive_window_adjust, libssh2), Culong, (Ptr{LIBSSH2_CHANNEL}, Culong, Cuchar), channel, adjustment, force)
end

function libssh2_channel_receive_window_adjust2(channel, adjustment, force, storewindow)
    ccall((:libssh2_channel_receive_window_adjust2, libssh2), Cint, (Ptr{LIBSSH2_CHANNEL}, Culong, Cuchar, Ptr{UInt32}), channel, adjustment, force, storewindow)
end

function libssh2_channel_write_ex(channel, stream_id, buf, buflen)
    ccall((:libssh2_channel_write_ex, libssh2), ssize_t, (Ptr{LIBSSH2_CHANNEL}, Cint, Cstring, Csize_t), channel, stream_id, buf, buflen)
end

function libssh2_channel_window_write_ex(channel, window_size_initial)
    ccall((:libssh2_channel_window_write_ex, libssh2), Culong, (Ptr{LIBSSH2_CHANNEL}, Ptr{Culong}), channel, window_size_initial)
end

function libssh2_session_set_blocking(session, blocking)
    ccall((:libssh2_session_set_blocking, libssh2), Cvoid, (Ptr{LIBSSH2_SESSION}, Cint), session, blocking)
end

function libssh2_session_get_blocking(session)
    ccall((:libssh2_session_get_blocking, libssh2), Cint, (Ptr{LIBSSH2_SESSION},), session)
end

function libssh2_channel_set_blocking(channel, blocking)
    ccall((:libssh2_channel_set_blocking, libssh2), Cvoid, (Ptr{LIBSSH2_CHANNEL}, Cint), channel, blocking)
end

function libssh2_session_set_timeout(session, timeout)
    ccall((:libssh2_session_set_timeout, libssh2), Cvoid, (Ptr{LIBSSH2_SESSION}, Clong), session, timeout)
end

function libssh2_session_get_timeout(session)
    ccall((:libssh2_session_get_timeout, libssh2), Clong, (Ptr{LIBSSH2_SESSION},), session)
end

function libssh2_channel_handle_extended_data(channel, ignore_mode)
    ccall((:libssh2_channel_handle_extended_data, libssh2), Cvoid, (Ptr{LIBSSH2_CHANNEL}, Cint), channel, ignore_mode)
end

function libssh2_channel_handle_extended_data2(channel, ignore_mode)
    ccall((:libssh2_channel_handle_extended_data2, libssh2), Cint, (Ptr{LIBSSH2_CHANNEL}, Cint), channel, ignore_mode)
end

function libssh2_channel_flush_ex(channel, streamid)
    ccall((:libssh2_channel_flush_ex, libssh2), Cint, (Ptr{LIBSSH2_CHANNEL}, Cint), channel, streamid)
end

function libssh2_channel_get_exit_status(channel)
    ccall((:libssh2_channel_get_exit_status, libssh2), Cint, (Ptr{LIBSSH2_CHANNEL},), channel)
end

function libssh2_channel_get_exit_signal(channel, exitsignal, exitsignal_len, errmsg, errmsg_len, langtag, langtag_len)
    ccall((:libssh2_channel_get_exit_signal, libssh2), Cint, (Ptr{LIBSSH2_CHANNEL}, Ptr{Cstring}, Ptr{Csize_t}, Ptr{Cstring}, Ptr{Csize_t}, Ptr{Cstring}, Ptr{Csize_t}), channel, exitsignal, exitsignal_len, errmsg, errmsg_len, langtag, langtag_len)
end

function libssh2_channel_send_eof(channel)
    ccall((:libssh2_channel_send_eof, libssh2), Cint, (Ptr{LIBSSH2_CHANNEL},), channel)
end

function libssh2_channel_eof(channel)
    ccall((:libssh2_channel_eof, libssh2), Cint, (Ptr{LIBSSH2_CHANNEL},), channel)
end

function libssh2_channel_wait_eof(channel)
    ccall((:libssh2_channel_wait_eof, libssh2), Cint, (Ptr{LIBSSH2_CHANNEL},), channel)
end

function libssh2_channel_close(channel)
    ccall((:libssh2_channel_close, libssh2), Cint, (Ptr{LIBSSH2_CHANNEL},), channel)
end

function libssh2_channel_wait_closed(channel)
    ccall((:libssh2_channel_wait_closed, libssh2), Cint, (Ptr{LIBSSH2_CHANNEL},), channel)
end

function libssh2_channel_free(channel)
    ccall((:libssh2_channel_free, libssh2), Cint, (Ptr{LIBSSH2_CHANNEL},), channel)
end

function libssh2_scp_recv(session, path, sb)
    ccall((:libssh2_scp_recv, libssh2), Ptr{LIBSSH2_CHANNEL}, (Ptr{LIBSSH2_SESSION}, Cstring, Ptr{stat}), session, path, sb)
end

function libssh2_scp_recv2(session, path, sb)
    ccall((:libssh2_scp_recv2, libssh2), Ptr{LIBSSH2_CHANNEL}, (Ptr{LIBSSH2_SESSION}, Cstring, Ptr{libssh2_struct_stat}), session, path, sb)
end

function libssh2_scp_send_ex(session, path, mode, size, mtime, atime)
    ccall((:libssh2_scp_send_ex, libssh2), Ptr{LIBSSH2_CHANNEL}, (Ptr{LIBSSH2_SESSION}, Cstring, Cint, Csize_t, Clong, Clong), session, path, mode, size, mtime, atime)
end

function libssh2_scp_send64(session, path, mode, size, mtime, atime)
    ccall((:libssh2_scp_send64, libssh2), Ptr{LIBSSH2_CHANNEL}, (Ptr{LIBSSH2_SESSION}, Cstring, Cint, libssh2_int64_t, Ctime_t, Ctime_t), session, path, mode, size, mtime, atime)
end

function libssh2_base64_decode(session, dest, dest_len, src, src_len)
    ccall((:libssh2_base64_decode, libssh2), Cint, (Ptr{LIBSSH2_SESSION}, Ptr{Cstring}, Ptr{UInt32}, Cstring, UInt32), session, dest, dest_len, src, src_len)
end

function libssh2_version(req_version_num)
    ccall((:libssh2_version, libssh2), Cstring, (Cint,), req_version_num)
end

function libssh2_knownhost_init(session)
    ccall((:libssh2_knownhost_init, libssh2), Ptr{LIBSSH2_KNOWNHOSTS}, (Ptr{LIBSSH2_SESSION},), session)
end

function libssh2_knownhost_add(hosts, host, salt, key, keylen, typemask, store)
    ccall((:libssh2_knownhost_add, libssh2), Cint, (Ptr{LIBSSH2_KNOWNHOSTS}, Cstring, Cstring, Cstring, Csize_t, Cint, Ptr{Ptr{libssh2_knownhost}}), hosts, host, salt, key, keylen, typemask, store)
end

function libssh2_knownhost_addc(hosts, host, salt, key, keylen, comment, commentlen, typemask, store)
    ccall((:libssh2_knownhost_addc, libssh2), Cint, (Ptr{LIBSSH2_KNOWNHOSTS}, Cstring, Cstring, Cstring, Csize_t, Cstring, Csize_t, Cint, Ptr{Ptr{libssh2_knownhost}}), hosts, host, salt, key, keylen, comment, commentlen, typemask, store)
end

function libssh2_knownhost_check(hosts, host, key, keylen, typemask, knownhost)
    ccall((:libssh2_knownhost_check, libssh2), Cint, (Ptr{LIBSSH2_KNOWNHOSTS}, Cstring, Cstring, Csize_t, Cint, Ptr{Ptr{libssh2_knownhost}}), hosts, host, key, keylen, typemask, knownhost)
end

function libssh2_knownhost_checkp(hosts, host, port, key, keylen, typemask, knownhost)
    ccall((:libssh2_knownhost_checkp, libssh2), Cint, (Ptr{LIBSSH2_KNOWNHOSTS}, Cstring, Cint, Cstring, Csize_t, Cint, Ptr{Ptr{libssh2_knownhost}}), hosts, host, port, key, keylen, typemask, knownhost)
end

function libssh2_knownhost_del(hosts, entry)
    ccall((:libssh2_knownhost_del, libssh2), Cint, (Ptr{LIBSSH2_KNOWNHOSTS}, Ptr{libssh2_knownhost}), hosts, entry)
end

function libssh2_knownhost_free(hosts)
    ccall((:libssh2_knownhost_free, libssh2), Cvoid, (Ptr{LIBSSH2_KNOWNHOSTS},), hosts)
end

function libssh2_knownhost_readline(hosts, line, len, type)
    ccall((:libssh2_knownhost_readline, libssh2), Cint, (Ptr{LIBSSH2_KNOWNHOSTS}, Cstring, Csize_t, Cint), hosts, line, len, type)
end

function libssh2_knownhost_readfile(hosts, filename, type)
    ccall((:libssh2_knownhost_readfile, libssh2), Cint, (Ptr{LIBSSH2_KNOWNHOSTS}, Cstring, Cint), hosts, filename, type)
end

function libssh2_knownhost_writeline(hosts, known, buffer, buflen, outlen, type)
    ccall((:libssh2_knownhost_writeline, libssh2), Cint, (Ptr{LIBSSH2_KNOWNHOSTS}, Ptr{libssh2_knownhost}, Cstring, Csize_t, Ptr{Csize_t}, Cint), hosts, known, buffer, buflen, outlen, type)
end

function libssh2_knownhost_writefile(hosts, filename, type)
    ccall((:libssh2_knownhost_writefile, libssh2), Cint, (Ptr{LIBSSH2_KNOWNHOSTS}, Cstring, Cint), hosts, filename, type)
end

function libssh2_knownhost_get(hosts, store, prev)
    ccall((:libssh2_knownhost_get, libssh2), Cint, (Ptr{LIBSSH2_KNOWNHOSTS}, Ptr{Ptr{libssh2_knownhost}}, Ptr{libssh2_knownhost}), hosts, store, prev)
end

function libssh2_agent_init(session)
    ccall((:libssh2_agent_init, libssh2), Ptr{LIBSSH2_AGENT}, (Ptr{LIBSSH2_SESSION},), session)
end

function libssh2_agent_connect(agent)
    ccall((:libssh2_agent_connect, libssh2), Cint, (Ptr{LIBSSH2_AGENT},), agent)
end

function libssh2_agent_list_identities(agent)
    ccall((:libssh2_agent_list_identities, libssh2), Cint, (Ptr{LIBSSH2_AGENT},), agent)
end

function libssh2_agent_get_identity(agent, store, prev)
    ccall((:libssh2_agent_get_identity, libssh2), Cint, (Ptr{LIBSSH2_AGENT}, Ptr{Ptr{libssh2_agent_publickey}}, Ptr{libssh2_agent_publickey}), agent, store, prev)
end

function libssh2_agent_userauth(agent, username, identity)
    ccall((:libssh2_agent_userauth, libssh2), Cint, (Ptr{LIBSSH2_AGENT}, Cstring, Ptr{libssh2_agent_publickey}), agent, username, identity)
end

function libssh2_agent_disconnect(agent)
    ccall((:libssh2_agent_disconnect, libssh2), Cint, (Ptr{LIBSSH2_AGENT},), agent)
end

function libssh2_agent_free(agent)
    ccall((:libssh2_agent_free, libssh2), Cvoid, (Ptr{LIBSSH2_AGENT},), agent)
end

function libssh2_agent_set_identity_path(agent, path)
    ccall((:libssh2_agent_set_identity_path, libssh2), Cvoid, (Ptr{LIBSSH2_AGENT}, Cstring), agent, path)
end

function libssh2_agent_get_identity_path(agent)
    ccall((:libssh2_agent_get_identity_path, libssh2), Cstring, (Ptr{LIBSSH2_AGENT},), agent)
end

function libssh2_keepalive_config(session, want_reply, interval)
    ccall((:libssh2_keepalive_config, libssh2), Cvoid, (Ptr{LIBSSH2_SESSION}, Cint, UInt32), session, want_reply, interval)
end

function libssh2_keepalive_send(session, seconds_to_next)
    ccall((:libssh2_keepalive_send, libssh2), Cint, (Ptr{LIBSSH2_SESSION}, Ptr{Cint}), session, seconds_to_next)
end

function libssh2_trace(session, bitmask)
    ccall((:libssh2_trace, libssh2), Cint, (Ptr{LIBSSH2_SESSION}, Cint), session, bitmask)
end

function libssh2_trace_sethandler(session, context, callback)
    ccall((:libssh2_trace_sethandler, libssh2), Cint, (Ptr{LIBSSH2_SESSION}, Ptr{Cvoid}, libssh2_trace_handler_func), session, context, callback)
end
