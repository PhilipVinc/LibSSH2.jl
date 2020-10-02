struct SSHHost
    address::String
    port::Int
end

SSHHost(address) = SSHHost(address, 22)
Base.isless(a::SSHHost, b::SSHHost) = isless(a.address, b.address) && isless(a.port, b.port)

function Base.show(io::IO, h::SSHHost)
    print(io, "SSHHost(\"$(h.address):$(h.port)\")")
end

struct SSHSession
    handle::Ptr{Cvoid}
    socket::TCPSocket
end

Base.convert(::Type{Ptr{LIBSSH2_SESSION}}, sess::SSHSession) = sess.handle
Base.unsafe_convert(::Type{Ptr{LIBSSH2_SESSION}}, sess::SSHSession) = convert(Ptr{LIBSSH2_SESSION}, sess.handle)

function SSHSession(host::SSHHost)
    sock = connect(host.address, host.port)

    sess = libssh2_session_init()

    libssh2_session_handshake(sess, sock)

    return SSHSession(sess, sock)
end

isauthenticated() = isauthenticated(current_ssh_session())
isauthenticated(session::SSHSession) = libssh2_userauth_authenticated(session) != 0

authenticate!(username, password) = authenticate!(current_ssh_session(), username, password)
authenticate!(session::SSHSession, username, password) = libssh2_userauth_password(session, username, password) == 0

struct SFTPSession
    handle::Ptr{Cvoid}
    ssh_session::SSHSession
end

Base.convert(::Type{Ptr{LIBSSH2_SFTP}}, sess::SFTPSession) = sess.handle
Base.unsafe_convert(::Type{Ptr{LIBSSH2_SFTP}}, sess::SFTPSession) = convert(Ptr{LIBSSH2_SFTP}, sess.handle)

function SFTPSession(session::SSHSession=current_ssh_session())
    sftp_sess = libssh2_sftp_init(session)
    return SFTPSession(sftp_sess, session)
end


## 
const _current_ssh_session = Ref{Union{SSHSession,Nothing}}(nothing)
const _current_sftp_session = Ref{Union{SFTPSession,Nothing}}(nothing)

function current_ssh_session()
	isnothing(_current_ssh_session[]) && throw("No SSH Session")
	return _current_ssh_session[]::SSHSession
end

function current_sftp_session()
	isnothing(_current_sftp_session[]) && set_current_session(SFTPSession(current_ssh_session()))
	return _current_sftp_session[]::SFTPSession
end

set_current_session(session::SSHSession) = _current_ssh_session[] = session
set_current_session(session::SFTPSession) = _current_sftp_session[] = session

libssh2_userauth_list(uname::String) = libssh2_userauth_list(current_ssh_session(), uname)
