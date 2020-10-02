const XFER_BUF_SIZE = 32767
const MB = 1048576

struct SFTPPath
    host::SSHHost
    path::String
end

function Base.show(io::IO, p::SFTPPath)
    print(io, "SFTPPath(\"$(p.host.address):$(p.host.port):$(p.path)\")")
end

SFTPPath(hostname::String, path) = SFTPPath(SSHHost(hostname), path)
SFTPPath(host::SSHHost, path) = SFTPPath(host, path)
Base.joinpath(p1::SFTPPath, p2::SFTPPath) = @assert p1.host === p2.host && return SFTPPath(p1.host, joinpath(p1.path, p2.path))
Base.joinpath(p1::SFTPPath, p2::AbstractString) = SFTPPath(p1.host, joinpath(p1.path, p2))
Base.basename(p::SFTPPath) = basename(p.path)
Base.endswith(p::SFTPPath, ending) = endswith(p.path, ending)
Base.isless(a::SFTPPath, b::SFTPPath) = isless(a.host, b.host) && isless(a.path, b.path)
Base.convert(T::Type{<:String}, p::SFTPPath) = p.path

struct SSHDirDescriptor
    handle::Ptr{Cvoid}
    session::SFTPSession
end

Base.convert(::Type{Ptr{LIBSSH2_SFTP_HANDLE}}, sess::SSHDirDescriptor) = sess.handle
Base.unsafe_convert(::Type{Ptr{LIBSSH2_SFTP_HANDLE}}, sess::SSHDirDescriptor) = convert(Ptr{LIBSSH2_SFTP_HANDLE}, sess.handle)

function sftp_open_dir(session::SFTPSession, path::AbstractString)
    dir_descriptor = libssh2_sftp_opendir(session, path)
    return SSHDirDescriptor(dir_descriptor, session)
end

sftp_open_dir(session::SFTPSession, path::SFTPPath) = sftp_open_dir(session, path.path)

Base.close(dir::SSHDirDescriptor) = libssh2_sftp_close_handle(dir)

Base.readdir(path::SFTPPath; kwargs...) =
    readdir(current_sftp_session(), path; kwargs...)

function Base.readdir(session::SFTPSession, path::SFTPPath; join::Bool=false, sort::Bool=true)
    dir = sftp_open_dir(session, path)

    entries = SFTPPath[]
    is_eof = false
    while true
        is_eof, name, info, attr = libssh2_sftp_readdir(dir, 2^8)
        is_eof && break
        (name == "." || name == "..") && continue
        fname = SFTPPath(path.host, name)
        push!(entries, join ? joinpath(path, fname) : fname)
    end

    sort && sort!(entries)

    close(dir)

    return entries
end

##
mutable struct SSHFileDescriptor <: IO
    handle::Ptr{Cvoid}
    session::SFTPSession
    eof::Bool
end

Base.convert(::Type{Ptr{LIBSSH2_SFTP_HANDLE}}, file::SSHFileDescriptor) = file.handle
Base.unsafe_convert(::Type{Ptr{LIBSSH2_SFTP_HANDLE}}, file::SSHFileDescriptor) = convert(Ptr{LIBSSH2_SFTP_HANDLE}, file.handle)

Base.close(file::SSHFileDescriptor) = libssh2_sftp_close_handle(file)
Base.eof(file::SSHFileDescriptor) = file.eof

Base.open(path::SFTPPath, args...; kwargs...) =
    Base.open(current_sftp_session(), path, args...; kwargs...)

function Base.open(session::SFTPSession, path::SFTPPath, mode::AbstractString; lock = true)
    mode == "r"  ? Base.open(session, path, lock = lock, read = true)                  :
    mode == "r+" ? Base.open(session, path, lock = lock, read = true, write = true)    :
    mode == "w"  ? Base.open(session, path, lock = lock, truncate = true)              :
    mode == "w+" ? Base.open(session, path, lock = lock, truncate = true, read = true) :
    mode == "a"  ? Base.open(session, path, lock = lock, append = true)                :
    mode == "a+" ? Base.open(session, path, lock = lock, append = true, read = true)   :
    throw(ArgumentError("invalid open mode: $mode"))
end

function Base.open(session::SFTPSession, path::SFTPPath; lock = true,
    read     :: Union{Bool,Nothing} = nothing,
    write    :: Union{Bool,Nothing} = nothing,
    create   :: Union{Bool,Nothing} = nothing,
    truncate :: Union{Bool,Nothing} = nothing,
    append   :: Union{Bool,Nothing} = nothing,
)
    flags = UInt32(0)

    flags = flags | ( read     == true ? LIBSSH2_FXF_READ   : 0x0 )
    flags = flags | ( write    == true ? LIBSSH2_FXF_WRITE  : 0x0 )
    flags = flags | ( create   == true ? LIBSSH2_FXF_CREAT  : 0x0 )
    flags = flags | ( truncate == true ? LIBSSH2_FXF_TRUNC  : 0x0 )
    flags = flags | ( append   == true ? LIBSSH2_FXF_APPEND : 0x0 )

    permissions = LIBSSH2_SFTP_S_IRUSR | LIBSSH2_SFTP_S_IWUSR | LIBSSH2_SFTP_S_IRGRP | LIBSSH2_SFTP_S_IROTH

    f_handle = libssh2_sftp_open(session, path.path, flags, permissions)

    return SSHFileDescriptor(f_handle, session, false)
end

Base.read(file::SFTPPath, args...) = read(current_sftp_session(), file, args...)
Base.read(session::SFTPSession, file::SFTPPath, args...) = open(io->read(io, args...), session, file)

Base.read(file::SFTPPath, ::Type{T}) where {T} = read(current_sftp_session(), file, T)
Base.read(session::SFTPSession, file::SFTPPath, ::Type{T}) where {T} = open(io->read(io, T), session, file)

Base.filesize(file::SFTPPath) = filesize(current_sftp_session(), file)
Base.filesize(session::SFTPSession, file::SFTPPath) = begin
    f = open(session, file)
    fs = filesize(f)
    close(f)
    return fs
end
Base.filesize(file::SSHFileDescriptor) = filesize(libssh2_sftp_fstat(file))

function unsafe_read_atmost(file::SSHFileDescriptor, p::Ptr{UInt8}, n::Int)
    nr = libssh2_sftp_read(file, p, n)
    if nr == 0
    	file.eof = true
    end
    @assert nr >= 0
    return nr
end

Base.readbytes_all!(s::SSHFileDescriptor, b::Array{UInt8}, nb) = begin
    GC.@preserve b begin
        ret = unsafe_read_atmost(s, pointer(b), length(b))
    end
    return ret
end

function Base.unsafe_read(file::SSHFileDescriptor, p::Ptr{UInt8}, n::UInt)
    nr = libssh2_sftp_read(file, p, n)
    if nr != n
    	file.eof = true
        throw(EOFError())
    end

    return nr
end

function Base.read(file::SSHFileDescriptor, ::Type{UInt8})
	mem = Ref(UInt8(0))
	b = unsafe_read(file, pointer_from_objref(mem), 1)
    return mem[]
end

function Base.readbytes!(s::SSHFileDescriptor, b::AbstractArray{UInt8}, nb=length(b))
    Base.require_one_based_indexing(b)
    olb = lb = length(b)
    nr = 0

    while !eof(s)
		if nr == lb
			lb = nr * 2
			resize!(b, lb)
		end

	    b_read = unsafe_read_atmost(s, pointer(b, nr+1), lb-nr)
	    nr += b_read
	end
    if nr != nb
    	resize!(b, nr)
    end
    return nr
end


function Base.unsafe_write(file::SSHFileDescriptor, p::Ptr{UInt8}, n::UInt)
    written::Int = 0
    written = libssh2_sftp_write(file, p, n)
    return written
end

function Base.write(file::SSHFileDescriptor, b::UInt8)
    #iswritable(s) || throw(ArgumentError("write failed, IOStream is not writeable"))
    mem = Ref(b)
    GC.@preserve mem begin
        retcode = unsafe_write(file, pointer_from_objref(mem), 1)
    end
    @assert retcode == 1
    return retcode
end

Base.seek(file::SSHFileDescriptor, pos::Integer) = libssh2_sftp_seek64(file, pos)
Base.position(file::SSHFileDescriptor) = convert(Int, libssh2_sftp_tell64(file))
Base.skip(file::SSHFileDescriptor, delta::Integer) = seek(file, position(file) + delta)
