# Julia wrapper for header: libssh2_publickey.h
# Automatically generated using Clang.jl


function libssh2_publickey_init(session)
    ccall((:libssh2_publickey_init, libssh2), Ptr{LIBSSH2_PUBLICKEY}, (Ptr{LIBSSH2_SESSION},), session)
end

function libssh2_publickey_add_ex(pkey, name, name_len, blob, blob_len, overwrite, num_attrs, attrs)
    ccall((:libssh2_publickey_add_ex, libssh2), Cint, (Ptr{LIBSSH2_PUBLICKEY}, Ptr{Cuchar}, Culong, Ptr{Cuchar}, Culong, UInt8, Culong, Ptr{libssh2_publickey_attribute}), pkey, name, name_len, blob, blob_len, overwrite, num_attrs, attrs)
end

function libssh2_publickey_remove_ex(pkey, name, name_len, blob, blob_len)
    ccall((:libssh2_publickey_remove_ex, libssh2), Cint, (Ptr{LIBSSH2_PUBLICKEY}, Ptr{Cuchar}, Culong, Ptr{Cuchar}, Culong), pkey, name, name_len, blob, blob_len)
end

function libssh2_publickey_list_fetch(pkey, num_keys, pkey_list)
    ccall((:libssh2_publickey_list_fetch, libssh2), Cint, (Ptr{LIBSSH2_PUBLICKEY}, Ptr{Culong}, Ptr{Ptr{libssh2_publickey_list}}), pkey, num_keys, pkey_list)
end

function libssh2_publickey_list_free(pkey, pkey_list)
    ccall((:libssh2_publickey_list_free, libssh2), Cvoid, (Ptr{LIBSSH2_PUBLICKEY}, Ptr{libssh2_publickey_list}), pkey, pkey_list)
end

function libssh2_publickey_shutdown(pkey)
    ccall((:libssh2_publickey_shutdown, libssh2), Cint, (Ptr{LIBSSH2_PUBLICKEY},), pkey)
end
