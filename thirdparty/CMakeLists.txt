# Initialize StormByte BuildMaster
add_subdirectory(buildmaster)
include(buildmaster/helpers.cmake)

# Construct StormByte Dependencies
add_subdirectory(StormByte)

# Construct Crypto++
add_subdirectory(Crypto++)

# Construct Bzip2
add_subdirectory(Bzip2)