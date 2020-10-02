# Automatically generated using Clang.jl


const LIBSSH2_H = 1
const LIBSSH2_COPYRIGHT = "2004-2019 The libssh2 project and its contributors."
const LIBSSH2_VERSION = "1.9.0"
const LIBSSH2_VERSION_MAJOR = 1
const LIBSSH2_VERSION_MINOR = 9
const LIBSSH2_VERSION_PATCH = 0
const LIBSSH2_VERSION_NUM = 0x00010900
const LIBSSH2_TIMESTAMP = "Thu Jun 20 06:19:26 UTC 2019"
const LIBSSH2_INVALID_SOCKET = -1
const LIBSSH2_STRUCT_STAT_SIZE_FORMAT = "%zd"
const LIBSSH2_SSH_BANNER = "SSH-2.0-libssh2_"
const LIBSSH2_SSH_DEFAULT_BANNER = LIBSSH2_SSH_BANNER
const LIBSSH2_SSH_DEFAULT_BANNER_WITH_CRLF = LIBSSH2_SSH_DEFAULT_BANNER
const LIBSSH2_DH_GEX_MINGROUP = 1024
const LIBSSH2_DH_GEX_OPTGROUP = 1536
const LIBSSH2_DH_GEX_MAXGROUP = 2048
const LIBSSH2_TERM_WIDTH = 80
const LIBSSH2_TERM_HEIGHT = 24
const LIBSSH2_TERM_WIDTH_PX = 0
const LIBSSH2_TERM_HEIGHT_PX = 0
const LIBSSH2_SOCKET_POLL_UDELAY = 250000
const LIBSSH2_SOCKET_POLL_MAXLOOPS = 120
const LIBSSH2_PACKET_MAXCOMP = 32000
const LIBSSH2_PACKET_MAXDECOMP = 40000
const LIBSSH2_PACKET_MAXPAYLOAD = 40000

# Skipping MacroDefinition: LIBSSH2_ALLOC_FUNC ( name ) void * name ( size_t count , void * * abstract )
# Skipping MacroDefinition: LIBSSH2_REALLOC_FUNC ( name ) void * name ( void * ptr , size_t count , void * * abstract )
# Skipping MacroDefinition: LIBSSH2_FREE_FUNC ( name ) void name ( void * ptr , void * * abstract )
# Skipping MacroDefinition: LIBSSH2_USERAUTH_PUBLICKEY_SIGN_FUNC ( name ) int name ( LIBSSH2_SESSION * session , unsigned char * * sig , size_t * sig_len , const unsigned char * data , size_t data_len , void * * abstract )
# Skipping MacroDefinition: LIBSSH2_USERAUTH_KBDINT_RESPONSE_FUNC ( name_ ) void name_ ( const char * name , int name_len , const char * instruction , int instruction_len , int num_prompts , const LIBSSH2_USERAUTH_KBDINT_PROMPT * prompts , LIBSSH2_USERAUTH_KBDINT_RESPONSE * responses , void * * abstract )
# Skipping MacroDefinition: LIBSSH2_IGNORE_FUNC ( name ) void name ( LIBSSH2_SESSION * session , const char * message , int message_len , void * * abstract )
# Skipping MacroDefinition: LIBSSH2_DEBUG_FUNC ( name ) void name ( LIBSSH2_SESSION * session , int always_display , const char * message , int message_len , const char * language , int language_len , void * * abstract )
# Skipping MacroDefinition: LIBSSH2_DISCONNECT_FUNC ( name ) void name ( LIBSSH2_SESSION * session , int reason , const char * message , int message_len , const char * language , int language_len , void * * abstract )
# Skipping MacroDefinition: LIBSSH2_PASSWD_CHANGEREQ_FUNC ( name ) void name ( LIBSSH2_SESSION * session , char * * newpw , int * newpw_len , void * * abstract )
# Skipping MacroDefinition: LIBSSH2_MACERROR_FUNC ( name ) int name ( LIBSSH2_SESSION * session , const char * packet , int packet_len , void * * abstract )
# Skipping MacroDefinition: LIBSSH2_X11_OPEN_FUNC ( name ) void name ( LIBSSH2_SESSION * session , LIBSSH2_CHANNEL * channel , const char * shost , int sport , void * * abstract )
# Skipping MacroDefinition: LIBSSH2_CHANNEL_CLOSE_FUNC ( name ) void name ( LIBSSH2_SESSION * session , void * * session_abstract , LIBSSH2_CHANNEL * channel , void * * channel_abstract )
# Skipping MacroDefinition: LIBSSH2_RECV_FUNC ( name ) ssize_t name ( libssh2_socket_t socket , void * buffer , size_t length , int flags , void * * abstract )
# Skipping MacroDefinition: LIBSSH2_SEND_FUNC ( name ) ssize_t name ( libssh2_socket_t socket , const void * buffer , size_t length , int flags , void * * abstract )

const LIBSSH2_CALLBACK_IGNORE = 0
const LIBSSH2_CALLBACK_DEBUG = 1
const LIBSSH2_CALLBACK_DISCONNECT = 2
const LIBSSH2_CALLBACK_MACERROR = 3
const LIBSSH2_CALLBACK_X11 = 4
const LIBSSH2_CALLBACK_SEND = 5
const LIBSSH2_CALLBACK_RECV = 6
const LIBSSH2_METHOD_KEX = 0
const LIBSSH2_METHOD_HOSTKEY = 1
const LIBSSH2_METHOD_CRYPT_CS = 2
const LIBSSH2_METHOD_CRYPT_SC = 3
const LIBSSH2_METHOD_MAC_CS = 4
const LIBSSH2_METHOD_MAC_SC = 5
const LIBSSH2_METHOD_COMP_CS = 6
const LIBSSH2_METHOD_COMP_SC = 7
const LIBSSH2_METHOD_LANG_CS = 8
const LIBSSH2_METHOD_LANG_SC = 9
const LIBSSH2_FLAG_SIGPIPE = 1
const LIBSSH2_FLAG_COMPRESS = 2
const LIBSSH2_POLLFD_SOCKET = 1
const LIBSSH2_POLLFD_CHANNEL = 2
const LIBSSH2_POLLFD_LISTENER = 3
const LIBSSH2_POLLFD_POLLIN = 0x0001
const LIBSSH2_POLLFD_POLLPRI = 0x0002
const LIBSSH2_POLLFD_POLLEXT = 0x0002
const LIBSSH2_POLLFD_POLLOUT = 0x0004
const LIBSSH2_POLLFD_POLLERR = 0x0008
const LIBSSH2_POLLFD_POLLHUP = 0x0010
const LIBSSH2_POLLFD_SESSION_CLOSED = 0x0010
const LIBSSH2_POLLFD_POLLNVAL = 0x0020
const LIBSSH2_POLLFD_POLLEX = 0x0040
const LIBSSH2_POLLFD_CHANNEL_CLOSED = 0x0080
const LIBSSH2_POLLFD_LISTENER_CLOSED = 0x0080
const LIBSSH2_SESSION_BLOCK_INBOUND = 0x0001
const LIBSSH2_SESSION_BLOCK_OUTBOUND = 0x0002
const LIBSSH2_HOSTKEY_HASH_MD5 = 1
const LIBSSH2_HOSTKEY_HASH_SHA1 = 2
const LIBSSH2_HOSTKEY_HASH_SHA256 = 3
const LIBSSH2_HOSTKEY_TYPE_UNKNOWN = 0
const LIBSSH2_HOSTKEY_TYPE_RSA = 1
const LIBSSH2_HOSTKEY_TYPE_DSS = 2
const LIBSSH2_HOSTKEY_TYPE_ECDSA_256 = 3
const LIBSSH2_HOSTKEY_TYPE_ECDSA_384 = 4
const LIBSSH2_HOSTKEY_TYPE_ECDSA_521 = 5
const LIBSSH2_HOSTKEY_TYPE_ED25519 = 6
const SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT = 1
const SSH_DISCONNECT_PROTOCOL_ERROR = 2
const SSH_DISCONNECT_KEY_EXCHANGE_FAILED = 3
const SSH_DISCONNECT_RESERVED = 4
const SSH_DISCONNECT_MAC_ERROR = 5
const SSH_DISCONNECT_COMPRESSION_ERROR = 6
const SSH_DISCONNECT_SERVICE_NOT_AVAILABLE = 7
const SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED = 8
const SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE = 9
const SSH_DISCONNECT_CONNECTION_LOST = 10
const SSH_DISCONNECT_BY_APPLICATION = 11
const SSH_DISCONNECT_TOO_MANY_CONNECTIONS = 12
const SSH_DISCONNECT_AUTH_CANCELLED_BY_USER = 13
const SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE = 14
const SSH_DISCONNECT_ILLEGAL_USER_NAME = 15
const LIBSSH2_ERROR_NONE = 0
const LIBSSH2_ERROR_SOCKET_NONE = -1
const LIBSSH2_ERROR_BANNER_RECV = -2
const LIBSSH2_ERROR_BANNER_SEND = -3
const LIBSSH2_ERROR_INVALID_MAC = -4
const LIBSSH2_ERROR_KEX_FAILURE = -5
const LIBSSH2_ERROR_ALLOC = -6
const LIBSSH2_ERROR_SOCKET_SEND = -7
const LIBSSH2_ERROR_KEY_EXCHANGE_FAILURE = -8
const LIBSSH2_ERROR_TIMEOUT = -9
const LIBSSH2_ERROR_HOSTKEY_INIT = -10
const LIBSSH2_ERROR_HOSTKEY_SIGN = -11
const LIBSSH2_ERROR_DECRYPT = -12
const LIBSSH2_ERROR_SOCKET_DISCONNECT = -13
const LIBSSH2_ERROR_PROTO = -14
const LIBSSH2_ERROR_PASSWORD_EXPIRED = -15
const LIBSSH2_ERROR_FILE = -16
const LIBSSH2_ERROR_METHOD_NONE = -17
const LIBSSH2_ERROR_AUTHENTICATION_FAILED = -18
const LIBSSH2_ERROR_PUBLICKEY_UNRECOGNIZED = LIBSSH2_ERROR_AUTHENTICATION_FAILED
const LIBSSH2_ERROR_PUBLICKEY_UNVERIFIED = -19
const LIBSSH2_ERROR_CHANNEL_OUTOFORDER = -20
const LIBSSH2_ERROR_CHANNEL_FAILURE = -21
const LIBSSH2_ERROR_CHANNEL_REQUEST_DENIED = -22
const LIBSSH2_ERROR_CHANNEL_UNKNOWN = -23
const LIBSSH2_ERROR_CHANNEL_WINDOW_EXCEEDED = -24
const LIBSSH2_ERROR_CHANNEL_PACKET_EXCEEDED = -25
const LIBSSH2_ERROR_CHANNEL_CLOSED = -26
const LIBSSH2_ERROR_CHANNEL_EOF_SENT = -27
const LIBSSH2_ERROR_SCP_PROTOCOL = -28
const LIBSSH2_ERROR_ZLIB = -29
const LIBSSH2_ERROR_SOCKET_TIMEOUT = -30
const LIBSSH2_ERROR_SFTP_PROTOCOL = -31
const LIBSSH2_ERROR_REQUEST_DENIED = -32
const LIBSSH2_ERROR_METHOD_NOT_SUPPORTED = -33
const LIBSSH2_ERROR_INVAL = -34
const LIBSSH2_ERROR_INVALID_POLL_TYPE = -35
const LIBSSH2_ERROR_PUBLICKEY_PROTOCOL = -36
const LIBSSH2_ERROR_EAGAIN = -37
const LIBSSH2_ERROR_BUFFER_TOO_SMALL = -38
const LIBSSH2_ERROR_BAD_USE = -39
const LIBSSH2_ERROR_COMPRESS = -40
const LIBSSH2_ERROR_OUT_OF_BOUNDARY = -41
const LIBSSH2_ERROR_AGENT_PROTOCOL = -42
const LIBSSH2_ERROR_SOCKET_RECV = -43
const LIBSSH2_ERROR_ENCRYPT = -44
const LIBSSH2_ERROR_BAD_SOCKET = -45
const LIBSSH2_ERROR_KNOWN_HOSTS = -46
const LIBSSH2_ERROR_CHANNEL_WINDOW_FULL = -47
const LIBSSH2_ERROR_KEYFILE_AUTH_FAILED = -48
const LIBSSH2_ERROR_BANNER_NONE = LIBSSH2_ERROR_BANNER_RECV
const LIBSSH2_INIT_NO_CRYPTO = 0x0001

# Skipping MacroDefinition: libssh2_session_init ( ) libssh2_session_init_ex ( NULL , NULL , NULL , NULL )
# Skipping MacroDefinition: libssh2_session_disconnect ( session , description ) libssh2_session_disconnect_ex ( ( session ) , SSH_DISCONNECT_BY_APPLICATION , ( description ) , "" )
# Skipping MacroDefinition: libssh2_userauth_password ( session , username , password ) libssh2_userauth_password_ex ( ( session ) , ( username ) , ( unsigned int ) strlen ( username ) , ( password ) , ( unsigned int ) strlen ( password ) , NULL )
# Skipping MacroDefinition: libssh2_userauth_publickey_fromfile ( session , username , publickey , privatekey , passphrase ) libssh2_userauth_publickey_fromfile_ex ( ( session ) , ( username ) , ( unsigned int ) strlen ( username ) , ( publickey ) , ( privatekey ) , ( passphrase ) )
# Skipping MacroDefinition: libssh2_userauth_hostbased_fromfile ( session , username , publickey , privatekey , passphrase , hostname ) libssh2_userauth_hostbased_fromfile_ex ( ( session ) , ( username ) , ( unsigned int ) strlen ( username ) , ( publickey ) , ( privatekey ) , ( passphrase ) , ( hostname ) , ( unsigned int ) strlen ( hostname ) , ( username ) , ( unsigned int ) strlen ( username ) )
# Skipping MacroDefinition: libssh2_userauth_keyboard_interactive ( session , username , response_callback ) libssh2_userauth_keyboard_interactive_ex ( ( session ) , ( username ) , ( unsigned int ) strlen ( username ) , ( response_callback ) )

const LIBSSH2_CHANNEL_WINDOW_DEFAULT = 2 * 1024 * 1024
const LIBSSH2_CHANNEL_PACKET_DEFAULT = 32768
const LIBSSH2_CHANNEL_MINADJUST = 1024
const LIBSSH2_CHANNEL_EXTENDED_DATA_NORMAL = 0
const LIBSSH2_CHANNEL_EXTENDED_DATA_IGNORE = 1
const LIBSSH2_CHANNEL_EXTENDED_DATA_MERGE = 2
const SSH_EXTENDED_DATA_STDERR = 1
const LIBSSH2CHANNEL_EAGAIN = LIBSSH2_ERROR_EAGAIN

# Skipping MacroDefinition: libssh2_channel_open_session ( session ) libssh2_channel_open_ex ( ( session ) , "session" , sizeof ( "session" ) - 1 , LIBSSH2_CHANNEL_WINDOW_DEFAULT , LIBSSH2_CHANNEL_PACKET_DEFAULT , NULL , 0 )
# Skipping MacroDefinition: libssh2_channel_direct_tcpip ( session , host , port ) libssh2_channel_direct_tcpip_ex ( ( session ) , ( host ) , ( port ) , "127.0.0.1" , 22 )
# Skipping MacroDefinition: libssh2_channel_forward_listen ( session , port ) libssh2_channel_forward_listen_ex ( ( session ) , NULL , ( port ) , NULL , 16 )
# Skipping MacroDefinition: libssh2_channel_setenv ( channel , varname , value ) libssh2_channel_setenv_ex ( ( channel ) , ( varname ) , ( unsigned int ) strlen ( varname ) , ( value ) , ( unsigned int ) strlen ( value ) )
# Skipping MacroDefinition: libssh2_channel_request_pty ( channel , term ) libssh2_channel_request_pty_ex ( ( channel ) , ( term ) , ( unsigned int ) strlen ( term ) , NULL , 0 , LIBSSH2_TERM_WIDTH , LIBSSH2_TERM_HEIGHT , LIBSSH2_TERM_WIDTH_PX , LIBSSH2_TERM_HEIGHT_PX )
# Skipping MacroDefinition: libssh2_channel_request_pty_size ( channel , width , height ) libssh2_channel_request_pty_size_ex ( ( channel ) , ( width ) , ( height ) , 0 , 0 )
# Skipping MacroDefinition: libssh2_channel_x11_req ( channel , screen_number ) libssh2_channel_x11_req_ex ( ( channel ) , 0 , NULL , NULL , ( screen_number ) )
# Skipping MacroDefinition: libssh2_channel_shell ( channel ) libssh2_channel_process_startup ( ( channel ) , "shell" , sizeof ( "shell" ) - 1 , NULL , 0 )
# Skipping MacroDefinition: libssh2_channel_exec ( channel , command ) libssh2_channel_process_startup ( ( channel ) , "exec" , sizeof ( "exec" ) - 1 , ( command ) , ( unsigned int ) strlen ( command ) )
# Skipping MacroDefinition: libssh2_channel_subsystem ( channel , subsystem ) libssh2_channel_process_startup ( ( channel ) , "subsystem" , sizeof ( "subsystem" ) - 1 , ( subsystem ) , ( unsigned int ) strlen ( subsystem ) )
# Skipping MacroDefinition: libssh2_channel_read ( channel , buf , buflen ) libssh2_channel_read_ex ( ( channel ) , 0 , ( buf ) , ( buflen ) )
# Skipping MacroDefinition: libssh2_channel_read_stderr ( channel , buf , buflen ) libssh2_channel_read_ex ( ( channel ) , SSH_EXTENDED_DATA_STDERR , ( buf ) , ( buflen ) )
# Skipping MacroDefinition: libssh2_channel_window_read ( channel ) libssh2_channel_window_read_ex ( ( channel ) , NULL , NULL )
# Skipping MacroDefinition: libssh2_channel_write ( channel , buf , buflen ) libssh2_channel_write_ex ( ( channel ) , 0 , ( buf ) , ( buflen ) )
# Skipping MacroDefinition: libssh2_channel_write_stderr ( channel , buf , buflen ) libssh2_channel_write_ex ( ( channel ) , SSH_EXTENDED_DATA_STDERR , ( buf ) , ( buflen ) )
# Skipping MacroDefinition: libssh2_channel_window_write ( channel ) libssh2_channel_window_write_ex ( ( channel ) , NULL )
# Skipping MacroDefinition: libssh2_channel_ignore_extended_data ( channel , ignore ) libssh2_channel_handle_extended_data ( ( channel ) , ( ignore ) ? LIBSSH2_CHANNEL_EXTENDED_DATA_IGNORE : LIBSSH2_CHANNEL_EXTENDED_DATA_NORMAL )

const LIBSSH2_CHANNEL_FLUSH_EXTENDED_DATA = -1
const LIBSSH2_CHANNEL_FLUSH_ALL = -2

# Skipping MacroDefinition: libssh2_channel_flush ( channel ) libssh2_channel_flush_ex ( ( channel ) , 0 )
# Skipping MacroDefinition: libssh2_channel_flush_stderr ( channel ) libssh2_channel_flush_ex ( ( channel ) , SSH_EXTENDED_DATA_STDERR )
# Skipping MacroDefinition: libssh2_scp_send ( session , path , mode , size ) libssh2_scp_send_ex ( ( session ) , ( path ) , ( mode ) , ( size ) , 0 , 0 )

const HAVE_LIBSSH2_KNOWNHOST_API = 0x00010101
const HAVE_LIBSSH2_VERSION_API = 0x00010100
const LIBSSH2_KNOWNHOST_TYPE_MASK = Float32(0x0fff)
const LIBSSH2_KNOWNHOST_TYPE_PLAIN = 1
const LIBSSH2_KNOWNHOST_TYPE_SHA1 = 2
const LIBSSH2_KNOWNHOST_TYPE_CUSTOM = 3
const LIBSSH2_KNOWNHOST_KEYENC_MASK = 3 << 16
const LIBSSH2_KNOWNHOST_KEYENC_RAW = 1 << 16
const LIBSSH2_KNOWNHOST_KEYENC_BASE64 = 2 << 16
const LIBSSH2_KNOWNHOST_KEY_MASK = 15 << 18
const LIBSSH2_KNOWNHOST_KEY_SHIFT = 18
const LIBSSH2_KNOWNHOST_KEY_RSA1 = 1 << 18
const LIBSSH2_KNOWNHOST_KEY_SSHRSA = 2 << 18
const LIBSSH2_KNOWNHOST_KEY_SSHDSS = 3 << 18
const LIBSSH2_KNOWNHOST_KEY_ECDSA_256 = 4 << 18
const LIBSSH2_KNOWNHOST_KEY_ECDSA_384 = 5 << 18
const LIBSSH2_KNOWNHOST_KEY_ECDSA_521 = 6 << 18
const LIBSSH2_KNOWNHOST_KEY_ED25519 = 7 << 18
const LIBSSH2_KNOWNHOST_KEY_UNKNOWN = 15 << 18
const LIBSSH2_KNOWNHOST_CHECK_MATCH = 0
const LIBSSH2_KNOWNHOST_CHECK_MISMATCH = 1
const LIBSSH2_KNOWNHOST_CHECK_NOTFOUND = 2
const LIBSSH2_KNOWNHOST_CHECK_FAILURE = 3
const LIBSSH2_KNOWNHOST_FILE_OPENSSH = 1
const HAVE_LIBSSH2_AGENT_API = 0x00010202
const LIBSSH2_TRACE_TRANS = 1 << 1
const LIBSSH2_TRACE_KEX = 1 << 2
const LIBSSH2_TRACE_AUTH = 1 << 3
const LIBSSH2_TRACE_CONN = 1 << 4
const LIBSSH2_TRACE_SCP = 1 << 5
const LIBSSH2_TRACE_SFTP = 1 << 6
const LIBSSH2_TRACE_ERROR = 1 << 7
const LIBSSH2_TRACE_PUBLICKEY = 1 << 8
const LIBSSH2_TRACE_SOCKET = 1 << 9
const libssh2_uint64_t = Culonglong
const libssh2_int64_t = Clonglong
#const libssh2_socket_t = Cint
const stat = Cvoid
const libssh2_struct_stat = stat
const libssh2_struct_stat_size = Cint

struct _LIBSSH2_USERAUTH_KBDINT_PROMPT
    text::Cstring
    length::UInt32
    echo::Cuchar
end

const LIBSSH2_USERAUTH_KBDINT_PROMPT = _LIBSSH2_USERAUTH_KBDINT_PROMPT

struct _LIBSSH2_USERAUTH_KBDINT_RESPONSE
    text::Cstring
    length::UInt32
end

const LIBSSH2_USERAUTH_KBDINT_RESPONSE = _LIBSSH2_USERAUTH_KBDINT_RESPONSE
const _LIBSSH2_SESSION = Cvoid
const LIBSSH2_SESSION = _LIBSSH2_SESSION
const _LIBSSH2_CHANNEL = Cvoid
const LIBSSH2_CHANNEL = _LIBSSH2_CHANNEL
const _LIBSSH2_LISTENER = Cvoid
const LIBSSH2_LISTENER = _LIBSSH2_LISTENER
const _LIBSSH2_KNOWNHOSTS = Cvoid
const LIBSSH2_KNOWNHOSTS = _LIBSSH2_KNOWNHOSTS
const _LIBSSH2_AGENT = Cvoid
const LIBSSH2_AGENT = _LIBSSH2_AGENT

struct ANONYMOUS1_fd
    channel::Ptr{LIBSSH2_CHANNEL}
end

struct _LIBSSH2_POLLFD
    type::Cuchar
    fd::ANONYMOUS1_fd
    events::Culong
    revents::Culong
end

const LIBSSH2_POLLFD = _LIBSSH2_POLLFD

struct libssh2_knownhost
    magic::UInt32
    node::Ptr{Cvoid}
    name::Cstring
    key::Cstring
    typemask::Cint
end

struct libssh2_agent_publickey
    magic::UInt32
    node::Ptr{Cvoid}
    blob::Ptr{Cuchar}
    blob_len::Csize_t
    comment::Cstring
end

const libssh2_trace_handler_func = Ptr{Cvoid}
const LIBSSH2_PUBLICKEY_H = 1

# Skipping MacroDefinition: libssh2_publickey_attribute ( name , value , mandatory ) { ( name ) , strlen ( name ) , ( value ) , strlen ( value ) , ( mandatory ) } ,
# Skipping MacroDefinition: libssh2_publickey_attribute_fast ( name , value , mandatory ) { ( name ) , sizeof ( name ) - 1 , ( value ) , sizeof ( value ) - 1 , ( mandatory ) } ,
# Skipping MacroDefinition: libssh2_publickey_add ( pkey , name , blob , blob_len , overwrite , num_attrs , attrs ) libssh2_publickey_add_ex ( ( pkey ) , ( name ) , strlen ( name ) , ( blob ) , ( blob_len ) , ( overwrite ) , ( num_attrs ) , ( attrs ) )
# Skipping MacroDefinition: libssh2_publickey_remove ( pkey , name , blob , blob_len ) libssh2_publickey_remove_ex ( ( pkey ) , ( name ) , strlen ( name ) , ( blob ) , ( blob_len ) )

const _LIBSSH2_PUBLICKEY = Cvoid
const LIBSSH2_PUBLICKEY = _LIBSSH2_PUBLICKEY

struct _libssh2_publickey_attribute
    name::Cstring
    name_len::Culong
    value::Cstring
    value_len::Culong
    mandatory::UInt8
end

const libssh2_publickey_attribute = _libssh2_publickey_attribute

struct _libssh2_publickey_list
    packet::Ptr{Cuchar}
    name::Ptr{Cuchar}
    name_len::Culong
    blob::Ptr{Cuchar}
    blob_len::Culong
    num_attrs::Culong
    attrs::Ptr{libssh2_publickey_attribute}
end

const libssh2_publickey_list = _libssh2_publickey_list
const LIBSSH2_SFTP_H = 1
const LIBSSH2_SFTP_VERSION = 3
const LIBSSH2_SFTP_OPENFILE = 0
const LIBSSH2_SFTP_OPENDIR = 1
const LIBSSH2_SFTP_RENAME_OVERWRITE = 0x00000001
const LIBSSH2_SFTP_RENAME_ATOMIC = 0x00000002
const LIBSSH2_SFTP_RENAME_NATIVE = 0x00000004
const LIBSSH2_SFTP_STAT = 0
const LIBSSH2_SFTP_LSTAT = 1
const LIBSSH2_SFTP_SETSTAT = 2
const LIBSSH2_SFTP_SYMLINK = 0
const LIBSSH2_SFTP_READLINK = 1
const LIBSSH2_SFTP_REALPATH = 2
const LIBSSH2_SFTP_DEFAULT_MODE = -1
const LIBSSH2_SFTP_ATTR_SIZE = 0x00000001
const LIBSSH2_SFTP_ATTR_UIDGID = 0x00000002
const LIBSSH2_SFTP_ATTR_PERMISSIONS = 0x00000004
const LIBSSH2_SFTP_ATTR_ACMODTIME = 0x00000008
const LIBSSH2_SFTP_ATTR_EXTENDED = 0x80000000
const LIBSSH2_SFTP_ST_RDONLY = 0x00000001
const LIBSSH2_SFTP_ST_NOSUID = 0x00000002
const LIBSSH2_SFTP_TYPE_REGULAR = 1
const LIBSSH2_SFTP_TYPE_DIRECTORY = 2
const LIBSSH2_SFTP_TYPE_SYMLINK = 3
const LIBSSH2_SFTP_TYPE_SPECIAL = 4
const LIBSSH2_SFTP_TYPE_UNKNOWN = 5
const LIBSSH2_SFTP_TYPE_SOCKET = 6
const LIBSSH2_SFTP_TYPE_CHAR_DEVICE = 7
const LIBSSH2_SFTP_TYPE_BLOCK_DEVICE = 8
const LIBSSH2_SFTP_TYPE_FIFO = 9
const LIBSSH2_SFTP_S_IFMT = 170000
const LIBSSH2_SFTP_S_IFIFO = 10000
const LIBSSH2_SFTP_S_IFCHR = 20000
const LIBSSH2_SFTP_S_IFDIR = 40000
const LIBSSH2_SFTP_S_IFBLK = 60000
const LIBSSH2_SFTP_S_IFREG = 100000
const LIBSSH2_SFTP_S_IFLNK = 120000
const LIBSSH2_SFTP_S_IFSOCK = 140000
const LIBSSH2_SFTP_S_IRWXU = 700
const LIBSSH2_SFTP_S_IRUSR = 400
const LIBSSH2_SFTP_S_IWUSR = 200
const LIBSSH2_SFTP_S_IXUSR = 100
const LIBSSH2_SFTP_S_IRWXG = 70
const LIBSSH2_SFTP_S_IRGRP = 40
const LIBSSH2_SFTP_S_IWGRP = 20
const LIBSSH2_SFTP_S_IXGRP = 10
const LIBSSH2_SFTP_S_IRWXO = 7
const LIBSSH2_SFTP_S_IROTH = 4
const LIBSSH2_SFTP_S_IWOTH = 2
const LIBSSH2_SFTP_S_IXOTH = 1

# Skipping MacroDefinition: LIBSSH2_SFTP_S_ISLNK ( m ) ( ( ( m ) & LIBSSH2_SFTP_S_IFMT ) == LIBSSH2_SFTP_S_IFLNK )
# Skipping MacroDefinition: LIBSSH2_SFTP_S_ISREG ( m ) ( ( ( m ) & LIBSSH2_SFTP_S_IFMT ) == LIBSSH2_SFTP_S_IFREG )
# Skipping MacroDefinition: LIBSSH2_SFTP_S_ISDIR ( m ) ( ( ( m ) & LIBSSH2_SFTP_S_IFMT ) == LIBSSH2_SFTP_S_IFDIR )
# Skipping MacroDefinition: LIBSSH2_SFTP_S_ISCHR ( m ) ( ( ( m ) & LIBSSH2_SFTP_S_IFMT ) == LIBSSH2_SFTP_S_IFCHR )
# Skipping MacroDefinition: LIBSSH2_SFTP_S_ISBLK ( m ) ( ( ( m ) & LIBSSH2_SFTP_S_IFMT ) == LIBSSH2_SFTP_S_IFBLK )
# Skipping MacroDefinition: LIBSSH2_SFTP_S_ISFIFO ( m ) ( ( ( m ) & LIBSSH2_SFTP_S_IFMT ) == LIBSSH2_SFTP_S_IFIFO )
# Skipping MacroDefinition: LIBSSH2_SFTP_S_ISSOCK ( m ) ( ( ( m ) & LIBSSH2_SFTP_S_IFMT ) == LIBSSH2_SFTP_S_IFSOCK )

const LIBSSH2_FXF_READ = 0x00000001
const LIBSSH2_FXF_WRITE = 0x00000002
const LIBSSH2_FXF_APPEND = 0x00000004
const LIBSSH2_FXF_CREAT = 0x00000008
const LIBSSH2_FXF_TRUNC = 0x00000010
const LIBSSH2_FXF_EXCL = 0x00000020
const LIBSSH2_FX_OK = 0
const LIBSSH2_FX_EOF = 1
const LIBSSH2_FX_NO_SUCH_FILE = 2
const LIBSSH2_FX_PERMISSION_DENIED = 3
const LIBSSH2_FX_FAILURE = 4
const LIBSSH2_FX_BAD_MESSAGE = 5
const LIBSSH2_FX_NO_CONNECTION = 6
const LIBSSH2_FX_CONNECTION_LOST = 7
const LIBSSH2_FX_OP_UNSUPPORTED = 8
const LIBSSH2_FX_INVALID_HANDLE = 9
const LIBSSH2_FX_NO_SUCH_PATH = 10
const LIBSSH2_FX_FILE_ALREADY_EXISTS = 11
const LIBSSH2_FX_WRITE_PROTECT = 12
const LIBSSH2_FX_NO_MEDIA = 13
const LIBSSH2_FX_NO_SPACE_ON_FILESYSTEM = 14
const LIBSSH2_FX_QUOTA_EXCEEDED = 15
const LIBSSH2_FX_UNKNOWN_PRINCIPLE = 16
const LIBSSH2_FX_UNKNOWN_PRINCIPAL = 16
const LIBSSH2_FX_LOCK_CONFlICT = 17
const LIBSSH2_FX_LOCK_CONFLICT = 17
const LIBSSH2_FX_DIR_NOT_EMPTY = 18
const LIBSSH2_FX_NOT_A_DIRECTORY = 19
const LIBSSH2_FX_INVALID_FILENAME = 20
const LIBSSH2_FX_LINK_LOOP = 21
const LIBSSH2SFTP_EAGAIN = LIBSSH2_ERROR_EAGAIN

# Skipping MacroDefinition: libssh2_sftp_open ( sftp , filename , flags , mode ) libssh2_sftp_open_ex ( ( sftp ) , ( filename ) , strlen ( filename ) , ( flags ) , ( mode ) , LIBSSH2_SFTP_OPENFILE )
# Skipping MacroDefinition: libssh2_sftp_opendir ( sftp , path ) libssh2_sftp_open_ex ( ( sftp ) , ( path ) , strlen ( path ) , 0 , 0 , LIBSSH2_SFTP_OPENDIR )
# Skipping MacroDefinition: libssh2_sftp_readdir ( handle , buffer , buffer_maxlen , attrs ) libssh2_sftp_readdir_ex ( ( handle ) , ( buffer ) , ( buffer_maxlen ) , NULL , 0 , ( attrs ) )
# Skipping MacroDefinition: libssh2_sftp_close ( handle ) libssh2_sftp_close_handle ( handle )
# Skipping MacroDefinition: libssh2_sftp_closedir ( handle ) libssh2_sftp_close_handle ( handle )
# Skipping MacroDefinition: libssh2_sftp_rewind ( handle ) libssh2_sftp_seek64 ( ( handle ) , 0 )
# Skipping MacroDefinition: libssh2_sftp_fstat ( handle , attrs ) libssh2_sftp_fstat_ex ( ( handle ) , ( attrs ) , 0 )
# Skipping MacroDefinition: libssh2_sftp_fsetstat ( handle , attrs ) libssh2_sftp_fstat_ex ( ( handle ) , ( attrs ) , 1 )
# Skipping MacroDefinition: libssh2_sftp_rename ( sftp , sourcefile , destfile ) libssh2_sftp_rename_ex ( ( sftp ) , ( sourcefile ) , strlen ( sourcefile ) , ( destfile ) , strlen ( destfile ) , LIBSSH2_SFTP_RENAME_OVERWRITE | LIBSSH2_SFTP_RENAME_ATOMIC | LIBSSH2_SFTP_RENAME_NATIVE )
# Skipping MacroDefinition: libssh2_sftp_unlink ( sftp , filename ) libssh2_sftp_unlink_ex ( ( sftp ) , ( filename ) , strlen ( filename ) )
# Skipping MacroDefinition: libssh2_sftp_mkdir ( sftp , path , mode ) libssh2_sftp_mkdir_ex ( ( sftp ) , ( path ) , strlen ( path ) , ( mode ) )
# Skipping MacroDefinition: libssh2_sftp_rmdir ( sftp , path ) libssh2_sftp_rmdir_ex ( ( sftp ) , ( path ) , strlen ( path ) )
# Skipping MacroDefinition: libssh2_sftp_stat ( sftp , path , attrs ) libssh2_sftp_stat_ex ( ( sftp ) , ( path ) , strlen ( path ) , LIBSSH2_SFTP_STAT , ( attrs ) )
# Skipping MacroDefinition: libssh2_sftp_lstat ( sftp , path , attrs ) libssh2_sftp_stat_ex ( ( sftp ) , ( path ) , strlen ( path ) , LIBSSH2_SFTP_LSTAT , ( attrs ) )
# Skipping MacroDefinition: libssh2_sftp_setstat ( sftp , path , attrs ) libssh2_sftp_stat_ex ( ( sftp ) , ( path ) , strlen ( path ) , LIBSSH2_SFTP_SETSTAT , ( attrs ) )
# Skipping MacroDefinition: libssh2_sftp_symlink ( sftp , orig , linkpath ) libssh2_sftp_symlink_ex ( ( sftp ) , ( orig ) , strlen ( orig ) , ( linkpath ) , strlen ( linkpath ) , LIBSSH2_SFTP_SYMLINK )
# Skipping MacroDefinition: libssh2_sftp_readlink ( sftp , path , target , maxlen ) libssh2_sftp_symlink_ex ( ( sftp ) , ( path ) , strlen ( path ) , ( target ) , ( maxlen ) , LIBSSH2_SFTP_READLINK )
# Skipping MacroDefinition: libssh2_sftp_realpath ( sftp , path , target , maxlen ) libssh2_sftp_symlink_ex ( ( sftp ) , ( path ) , strlen ( path ) , ( target ) , ( maxlen ) , LIBSSH2_SFTP_REALPATH )

const _LIBSSH2_SFTP = Cvoid
const LIBSSH2_SFTP = _LIBSSH2_SFTP
const _LIBSSH2_SFTP_HANDLE = Cvoid
const LIBSSH2_SFTP_HANDLE = _LIBSSH2_SFTP_HANDLE

struct _LIBSSH2_SFTP_ATTRIBUTES
    flags::Culong
    filesize::libssh2_uint64_t
    uid::Culong
    gid::Culong
    permissions::Culong
    atime::Culong
    mtime::Culong
end

const LIBSSH2_SFTP_ATTRIBUTES = _LIBSSH2_SFTP_ATTRIBUTES

struct _LIBSSH2_SFTP_STATVFS
    f_bsize::libssh2_uint64_t
    f_frsize::libssh2_uint64_t
    f_blocks::libssh2_uint64_t
    f_bfree::libssh2_uint64_t
    f_bavail::libssh2_uint64_t
    f_files::libssh2_uint64_t
    f_ffree::libssh2_uint64_t
    f_favail::libssh2_uint64_t
    f_fsid::libssh2_uint64_t
    f_flag::libssh2_uint64_t
    f_namemax::libssh2_uint64_t
end

const LIBSSH2_SFTP_STATVFS = _LIBSSH2_SFTP_STATVFS
