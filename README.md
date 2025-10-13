# Slhasher

Slhasher is a command-line tool that allows you to compute the hash of a file or a string of characters, using several cryptographic hash functions.

## Features and usage

The current version of Slhasher (1.0) features the following cryptographic hash functions:

- MD5

- SHA-1

- SHA-2:
    - SHA-224
    - SHA-256
    - SHA-384
    - SHA-512
    - SHA-512/224
    - SHA-512/256

- SHA-3:
    - SHA3-224
    - SHA3-256
    - SHA3-284
    - SHA3-512

- To use a function, you have to type its name, preceded by to dashes ('--').
Example: slhasher --sha256 file1.exe

- If you wish to check a file's integrity by comparing the file's hash to a reference hash, type the reference hash (in hexadecimal) after the source.

Example: slhasher --sha512 file2.txt <reference hash>

The arguments' order does not matter, except that you always have to type the source (a file name or a string of characters) 
**before** the reference hash.

- If you have a sum file at your disposal (I call a sum file a file that contains a file's name and that file's hash), you can pass that sum file as an argument, along with
the --sumfile flag, and Slhasher will open it, read its content, then check if the file whose name is written in the sum file produces a hash that is identical to the
hash written in the sum file. In order for the operation to work, both the file and the sum file must be stored in the same directory.

Example: the file3.AppImage.sha256 sum file contains: <SHA-256 hash of file3.AppImage>  file3.AppImage
		 to use --sumfile: slhasher --sha256 --sumfile file3.AppImage.sha256

- As previously stated, you can compute the hash of a string of characters, by using the --string flag.

Example: slhasher --sha1 --string "Let's make more free and open-source softwares!"

- If you want to have help printed in the terminal, you can use the --help flag.

Example: slhasher --help

- You can also print your version of Slhasher in the terminal using the --version flag.

Example: slhasher --version

## Build and install

To build Slhasher, you will need a C compiler. The right compiler depends on your operating system (gcc for Linux and Windows, clang for macOS).

In order to build Slhasher from source, first clone the repository with: git clone https://github.com/absoluteseeker/slhasher.git 

Then, go in the slhasher directory and type: make

This will create an executable file called "slhasher" in the slhasher/build directory.

Then, to install, type: make install

This will copy the executable in an appropriate location. That will allow you to use Slhasher from any location in your file tree. 

You may need to use the sudo command for this operation. If that is the case, first type: sudo make install, then, your root password.

## Philosophy

Slhasher was created to render the use of the main cryptographic hash functions easier (several of them can be used with the same command), thus making the
task of checking a program's integrity faster and (I hope) more pleasant (or at least less painful). Moreover, it is intended to be cross-platform. For now
you can only build from source. That can make Slhasher more performant, since the code will be specifically compiled for your particular machine, 
but the operation might not be easy if you never did it before. That is why I will provide precompiled binaries for the most popular operating systems
in future versions, to make Slhasher both cross-platform and user-friendly.  

Slhasher currently features some of the most popular cryptographic hash functions (MD5, SHA-1, SHA-2...). Other functions will be added in future versions,
to add more diversity and make rare cryptographic hash functions more accessible and easier to use.

## License

Slhasher is published under the GNU General Public License version 3. See the LICENSE.md file for more details.

## Contact informations

You can contact me by email at: absoluteseeker@proton.me. I strongly encourage you to encrypt your message with this address's public key, and to provide
your public key with your message so that I can encrypt my response.
