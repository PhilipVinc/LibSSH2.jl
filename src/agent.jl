struct SSHAgent
    handle::Ptr{Cvoid}
    session::SSHSession
end

Base.convert(::Type{Ptr{LIBSSH2_AGENT}}, ag::SSHAgent) = ag.handle
Base.unsafe_convert(::Type{Ptr{LIBSSH2_AGENT}}, ag::SSHAgent) = convert(Ptr{LIBSSH2_AGENT}, ag.handle)

SSHAgent(session::SSHSession) = SSHAgent(libssh2_agent_init(session), session)

Sockets.connect(agent::SSHAgent) = libssh2_agent_connect(agent) == 0
disconnect(agent::SSHAgent) = libssh2_agent_disconnect(agent) == 0
free(agent::SSHAgent) = libssh2_agent_free(agent)
