# Julia wrapper for header: libssh2_sftp.h
# Automatically generated using Clang.jl


function libssh2_sftp_init(session)
    ccall((:libssh2_sftp_init, libssh2), Ptr{LIBSSH2_SFTP}, (Ptr{LIBSSH2_SESSION},), session)
end

function libssh2_sftp_shutdown(sftp)
    ccall((:libssh2_sftp_shutdown, libssh2), Cint, (Ptr{LIBSSH2_SFTP},), sftp)
end

function libssh2_sftp_last_error(sftp)
    ccall((:libssh2_sftp_last_error, libssh2), Culong, (Ptr{LIBSSH2_SFTP},), sftp)
end

function libssh2_sftp_get_channel(sftp)
    ccall((:libssh2_sftp_get_channel, libssh2), Ptr{LIBSSH2_CHANNEL}, (Ptr{LIBSSH2_SFTP},), sftp)
end

function libssh2_sftp_open_ex(sftp, filename, filename_len, flags, mode, open_type)
    ccall((:libssh2_sftp_open_ex, libssh2), Ptr{LIBSSH2_SFTP_HANDLE}, (Ptr{LIBSSH2_SFTP}, Cstring, UInt32, Culong, Clong, Cint), sftp, filename, filename_len, flags, mode, open_type)
end

function libssh2_sftp_read(handle, buffer, maxlen)
    ccall((:libssh2_sftp_read, libssh2), Cint, (Ptr{LIBSSH2_SFTP_HANDLE}, Cstring, Csize_t), handle, buffer, maxlen)
end

function libssh2_sftp_readdir_ex(handle, buffer, buffer_maxlen, longentry, longentry_maxlen, attrs)
    ccall((:libssh2_sftp_readdir_ex, libssh2), Cint, (Ptr{LIBSSH2_SFTP_HANDLE}, Cstring, Csize_t, Cstring, Csize_t, Ptr{LIBSSH2_SFTP_ATTRIBUTES}), handle, buffer, buffer_maxlen, longentry, longentry_maxlen, attrs)
end

function libssh2_sftp_write()
    ccall((:libssh2_sftp_write, libssh2), Cint, ())
end

function libssh2_sftp_fsync(handle)
    ccall((:libssh2_sftp_fsync, libssh2), Cint, (Ptr{LIBSSH2_SFTP_HANDLE},), handle)
end

function libssh2_sftp_close_handle(handle)
    ccall((:libssh2_sftp_close_handle, libssh2), Cint, (Ptr{LIBSSH2_SFTP_HANDLE},), handle)
end

function libssh2_sftp_seek(handle, offset)
    ccall((:libssh2_sftp_seek, libssh2), Cvoid, (Ptr{LIBSSH2_SFTP_HANDLE}, Csize_t), handle, offset)
end

function libssh2_sftp_seek64(handle, offset)
    ccall((:libssh2_sftp_seek64, libssh2), Cvoid, (Ptr{LIBSSH2_SFTP_HANDLE}, libssh2_uint64_t), handle, offset)
end

function libssh2_sftp_tell(handle)
    ccall((:libssh2_sftp_tell, libssh2), Csize_t, (Ptr{LIBSSH2_SFTP_HANDLE},), handle)
end

function libssh2_sftp_tell64(handle)
    ccall((:libssh2_sftp_tell64, libssh2), libssh2_uint64_t, (Ptr{LIBSSH2_SFTP_HANDLE},), handle)
end

function libssh2_sftp_fstat_ex(handle, attrs, setstat)
    ccall((:libssh2_sftp_fstat_ex, libssh2), Cint, (Ptr{LIBSSH2_SFTP_HANDLE}, Ptr{LIBSSH2_SFTP_ATTRIBUTES}, Cint), handle, attrs, setstat)
end

function libssh2_sftp_rename_ex(sftp, source_filename, srouce_filename_len, dest_filename, dest_filename_len, flags)
    ccall((:libssh2_sftp_rename_ex, libssh2), Cint, (Ptr{LIBSSH2_SFTP}, Cstring, UInt32, Cstring, UInt32, Clong), sftp, source_filename, srouce_filename_len, dest_filename, dest_filename_len, flags)
end

function libssh2_sftp_unlink_ex(sftp, filename, filename_len)
    ccall((:libssh2_sftp_unlink_ex, libssh2), Cint, (Ptr{LIBSSH2_SFTP}, Cstring, UInt32), sftp, filename, filename_len)
end

function libssh2_sftp_fstatvfs(handle, st)
    ccall((:libssh2_sftp_fstatvfs, libssh2), Cint, (Ptr{LIBSSH2_SFTP_HANDLE}, Ptr{LIBSSH2_SFTP_STATVFS}), handle, st)
end

function libssh2_sftp_statvfs(sftp, path, path_len, st)
    ccall((:libssh2_sftp_statvfs, libssh2), Cint, (Ptr{LIBSSH2_SFTP}, Cstring, Csize_t, Ptr{LIBSSH2_SFTP_STATVFS}), sftp, path, path_len, st)
end

function libssh2_sftp_mkdir_ex(sftp, path, path_len, mode)
    ccall((:libssh2_sftp_mkdir_ex, libssh2), Cint, (Ptr{LIBSSH2_SFTP}, Cstring, UInt32, Clong), sftp, path, path_len, mode)
end

function libssh2_sftp_rmdir_ex(sftp, path, path_len)
    ccall((:libssh2_sftp_rmdir_ex, libssh2), Cint, (Ptr{LIBSSH2_SFTP}, Cstring, UInt32), sftp, path, path_len)
end

function libssh2_sftp_stat_ex(sftp, path, path_len, stat_type, attrs)
    ccall((:libssh2_sftp_stat_ex, libssh2), Cint, (Ptr{LIBSSH2_SFTP}, Cstring, UInt32, Cint, Ptr{LIBSSH2_SFTP_ATTRIBUTES}), sftp, path, path_len, stat_type, attrs)
end

function libssh2_sftp_symlink_ex(sftp, path, path_len, target, target_len, link_type)
    ccall((:libssh2_sftp_symlink_ex, libssh2), Cint, (Ptr{LIBSSH2_SFTP}, Cstring, UInt32, Cstring, UInt32, Cint), sftp, path, path_len, target, target_len, link_type)
end
