
module LibSSH2

using LibSSH2_jll
using Sockets
using FilePathsBase

function __init__()
    rc=LibSSH2.libssh2_init(0)
	atexit(()->libssh2_exit())
end

struct libssh2_socket_t
    descriptor::Cint
end
Base.cconvert(::Type{libssh2_socket_t}, sock::TCPSocket) = libssh2_socket_t(reinterpret(Cint, Base._fd(sock)))

const ssize_t = Csize_t

include("ctypes.jl")
include("libssh2/libssh2_api.jl")
include("libssh2/libssh2_h.jl")
include("libssh2/libssh2_publickey_h.jl")
include("libssh2/libssh2_sftp_h.jl")

version() = unsafe_string(libssh2_version(0))

libssh2_session_init() = libssh2_session_init_ex(C_NULL, C_NULL, C_NULL, C_NULL)
libssh2_userauth_password(sess, uname, passwd) = libssh2_userauth_password_ex(sess, uname, length(uname), passwd, length(passwd), C_NULL)
libssh2_userauth_publickey_fromfile(sess, uname, publickey, privatekey, passphrase=C_NULL) = libssh2_userauth_publickey_fromfile_ex(sess, uname, length(uname), publickey, privatekey, passphrase)
libssh2_userauth_list(sess, uname) = unsafe_string(libssh2_userauth_list(sess, uname, length(uname)))

libssh2_sftp_opendir(sftp, path) = libssh2_sftp_open_ex(sftp, path, length(path), 0, 0, LIBSSH2_SFTP_OPENDIR)
libssh2_sftp_open(sftp, filename, flags, mode) = libssh2_sftp_open_ex(sftp, filename, length(filename), flags, mode, LIBSSH2_SFTP_OPENFILE)

function libssh2_sftp_fstat(handle)
	attr=Ref(LibSSH2.LIBSSH2_SFTP_ATTRIBUTES(0,0,0,0,0,0,0))
	GC.@preserve attr begin
	    ret = LibSSH2.libssh2_sftp_fstat_ex(handle, attr, 0)
	end
	@assert ret == 0
	return attr[]
end

Base.filesize(attr::LIBSSH2_SFTP_ATTRIBUTES) = convert(Int, attr.filesize)

function libssh2_sftp_fstat!(handle, attr)
	_attr=Ref(attr)
	GC.@preserve _attr begin
	    ret = LibSSH2.libssh2_sftp_fstat_ex(handle, _attr, 1)
	end
	@assert ret == 0
	return handle
end

function libssh2_sftp_readdir(dir, max_size=2^8)
	namebuf = Vector{UInt8}(undef, max_size)
	infobuf = Vector{UInt8}(undef, max_size)
	attr=Ref(LibSSH2.LIBSSH2_SFTP_ATTRIBUTES(0,0,0,0,0,0,0))

	GC.@preserve namebuf infobuf begin
	    ret = LibSSH2.libssh2_sftp_readdir_ex(dir, pointer(namebuf), length(namebuf), pointer(infobuf), length(infobuf), attr)
	end

	@assert ret >= 0
	is_eof = ret == 0

	name = unsafe_string(pointer(namebuf))
	info = unsafe_string(pointer(infobuf))
	return is_eof, name, info, attr[]
end

libssh2_session_last_error() = libssh2_session_last_error(current_ssh_session())
function libssh2_session_last_error(session)
	string_pt = Ref(Cstring(Ptr{UInt8}()))
	len_pt = Ref(Cint(1))
	err_code = libssh2_session_last_error(session, string_pt, len_pt, 0)
	return unsafe_string(string_pt[]), err_code
end

include("session.jl")
include("agent.jl")
include("interface.jl")

end
