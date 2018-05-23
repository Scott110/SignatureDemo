# For more information about using CMake with Android Studio, read the
# documentation: https://d.android.com/studio/projects/add-native-code.html

# 构建cmake 所需要的最小版本号

cmake_minimum_required(VERSION 3.4.1)

# 编译预配置 C++ 的版本为11
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=gnu++11")

#设置生成的so动态库最后输出的路径
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR}/../libsignature/jniLibs/${ANDROID_ABI})



#如何编译一个目录中所有源文件
aux_source_directory(${CMAKE_SOURCE_DIR}/../libsignature/src/main/cpp SRC_LIST)

list(APPEND SRC_LIST)

aux_source_directory(${CMAKE_SOURCE_DIR}/../libsignature/src/main/cpp/zip ZIP_SRC_LIST)

list(APPEND ZIP_SRC_LIST)



# 创建命名一个库将其设置为 STATIC
# or SHARED, 并且提供源码的相对路径
# 你可以定义多个库 CMake 会为你创建
# Gradle 会自动将共享库和你的apk 关联
add_library( # Sets the name of the library.
              zto-signature

             # Sets the library as a shared library.
             SHARED

             # Provides a relative path to your source file(s).
             ${SRC_LIST}

             ${ZIP_SRC_LIST}

             )

#搜索特定的预制的库并且存储他的路径,作为一个参数，默认cmake 包含系统库的路径，如果你想要用只需要在制定在ndk库中的名称。
#在构建完成之前camke 会检查库是否存在

find_library( # Sets the name of the path variable.
              log-lib

              # Specifies the name of the NDK library that
              # you want CMake to locate.
              log )

find_library( # Sets the name of the path variable.
              z-lib

              # Specifies the name of the NDK library that
              # you want CMake to locate.
              z )



find_library(graphics

             jnigraphics)


#配置包含的文件（头文件）
target_include_directories(zto-signature PRIVATE
                           ${SRC_LIST}/include
                           ${ZIP_SRC_LIST}/include
                           )

#指定那些库Cmake应该链接到目标库，你可以链接多个库，可以是系统库也可以是第三方库

target_link_libraries( # Specifies the target library.
                       zto-signature

                       # Links the target library to the log library
                       # included in the NDK.
                       ${log-lib}

                       ${z-lib}

                       ${graphics}

                       )