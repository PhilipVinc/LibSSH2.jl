using Clang
using Clang.LibClang.Clang_jll

using Printf

using Clang: CLANG_INCLUDE
using Clang: find_std_headers

# Set these to correspond to your local filesystem's curl and clang include paths
const LIBSSH2_PATH = "/Users/filippovicentini/Documents/ssh/libssh2-1.9.0"
const LIBSSH2_SRC_PATH = LIBSSH2_PATH*"/src"
const LIBSSH2_INCLUDE_PATH = LIBSSH2_PATH*"/include"

HEADERS = [joinpath(LIBSSH2_INCLUDE_PATH, header) for header in readdir(LIBSSH2_INCLUDE_PATH) if endswith(header, ".h")]

COMMON_HEADERS = [joinpath(LIBSSH2_SRC_PATH, header) for header in readdir(LIBSSH2_SRC_PATH) if endswith(header, ".h")]
CLANG_INCLUDES = [CLANG_INCLUDE]

SRC_DIR = "../src/libssh2"
mkpath(SRC_DIR)

clang_args = String[]

if Sys.isapple()
    for header in find_std_headers()
        push!(clang_args, "-I"*header)
    end
end

included_from = Dict()
function wrap_header(root, current)
    return any(header->endswith(current, header), HEADERS) &&
           get!(included_from, current, root) == root
end

context = init(; headers = HEADERS,
            clang_args = clang_args,
            output_file = joinpath(SRC_DIR, "libssh2_api.jl"),
            clang_includes = CLANG_INCLUDES,
            header_wrapped = wrap_header,
            header_library = x->"libssh2",
            header_outputfile = header -> begin
                p1 = SRC_DIR
                p2 = replace(basename(header), "." => "_") * ".jl"
                @info header p1 p2
                joinpath(p1,p2)
            end,
            clang_diagnostics = true,
            )

context.options.wrap_structs = true

run(context, false)

output_files = readdir(SRC_DIR, join=true)

using CSTParser, Tokenize

struct Edit{T}
    loc::T
    text::String
end

function pass(x, state, f = (x, state)->nothing)
    f(x, state)
    if x.args isa Vector
        for a in x.args
            pass(a, state, f)
        end
    else
        state.offset += x.fullspan
    end
    state
end

function apply(text, edit::Edit{Int})
    string(text[1:edit.loc], edit.text, text[nextind(text, edit.loc):end])
end
function apply(text, edit::Edit{UnitRange{Int}})
    # println("Rewriting '$(text[edit.loc])' to '$(edit.text)'")
    string(text[1:prevind(text, first(edit.loc))], edit.text, text[nextind(text, last(edit.loc)):end])
end








function process(name, headers...; libname=name, kwargs...)
    new_output_file, new_common_file = wrap(libname, headers...; kwargs...)

    for file in (new_output_file, new_common_file)
        text = read(file, String)

        ## rewriting passes

        state = State(0, Edit[])
        ast = CSTParser.parse(text, true)

        state.offset = 0
        pass(ast, state, insert_check_pass)

        # apply
        state.offset = 0
        sort!(state.edits, lt = (a,b) -> first(a.loc) < first(b.loc), rev = true)
        for i = 1:length(state.edits)
            text = apply(text, state.edits[i])
        end

        ## header

        squeezed = replace(text, "\n\n\n"=>"\n\n")
        while length(text) != length(squeezed)
            text = squeezed
            squeezed = replace(text, "\n\n\n"=>"\n\n")
        end
        text = squeezed


        write(file, text)
    end

#=
function write_constants(filename::AbstractString, startswith_identifier::AbstractString, exports_file)
    open(filename, "r") do file
        lines = split(read(file, String), "\n")

        for line in lines
            if startswith(line, startswith_identifier)
                @printf exports_file "export %s\n" split(line, r" |\(")[2]
            end
        end
    end
end

# Generate export statements
open(joinpath(SRC_DIR, "libssh2_exports_h.jl"), "w+") do exports_file
    println(exports_file, "#   Generating exports")

    write_constants(joinpath(SRC_DIR, "libssh2_curl_h.jl"), "function", exports_file)
    write_constants(joinpath(SRC_DIR, "lC_common_h.jl"), "const", exports_file)

    # Generate define constants
    open(joinpath(SRC_DIR, "lC_defines_h.jl"), "w+") do defines_file
        println(defines_file, "#   Generating #define constants")

        hashdefs = split(read(`gcc -E -dD -P $(joinpath(LIBSSH2_PATH, "curl.h"))`, String), "\n")

        for line in hashdefs
            m = match(r"^\s*#define\s+CURL(\w+)\s+(.+)", line)

            if m !== nothing
                c2 = replace(m.captures[2], "(unsigned long)" => "")
                @printf defines_file "const CURL%-30s = %s\n"  m.captures[1]  c2
                @printf exports_file "export CURL%s\n"  m.captures[1]
            end
        end
    end
end
=#