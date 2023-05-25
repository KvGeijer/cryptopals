# Script generated completely by ChatGPT-4
# Basically at least, no error/problem when not touching it myself

using ArgParse
using JSON

function count_chars(file_path)
    if !isfile(file_path)
        error("File does not exist: $file_path")
    end

    # Read file and convert to a list of characters
    text = read(file_path, String)
    char_list = collect(text)
    
    # Count occurrences
    char_counts = Dict{Char, Int}()
    for char in char_list
        # Only count alphabetical characters and whitespaces
        if isletter(char) || char == ' '
            char_counts[char] = get(char_counts, char, 0) + 1
        end
    end
    total_chars = sum(values(char_counts))

    # Convert to percentages
    char_percentages = Dict{Char, Float64}()
    for (char, count) in char_counts
        char_percentages[char] = count / total_chars
    end

    return char_percentages
end

function write_to_json(data, output_path)
    open(output_path, "w") do f
        write(f, JSON.json(data, 4))
    end
end

function parse_commandline()
    s = ArgParseSettings()

    @add_arg_table! s begin
        "--input"
            help = "path to the input txt file"
            required = true
        "--output"
            help = "path to the output json file"
            required = true
    end

    return parse_args(s)
end

# Parse command line arguments
args = parse_commandline()

file_path = args["input"]
output_path = args["output"]

# Count characters
char_percentages = count_chars(file_path)

# Write data to JSON
write_to_json(char_percentages, output_path)
