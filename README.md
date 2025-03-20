# COMP4985-Client Repository Guide

Welcome to the `COMP498-client-project` repository. This guide will help you set up the client project,
and run the program

## **Table of Contents**

1. [Cloning the Repository](#cloning-the-repository)
2. [Creating links to the repository](#creating-links-to-the-repository)
3. [Running the `generate-cmakelists.sh` Script](#running-the-generate-cmakelistssh-script)
4. [Running the `change-compiler.sh` Script](#running-the-change-compilersh-script)
5. [Building the program with GCC](#building-the-program-with-gcc)
6. [Running the program](#running-the-program)

## **Cloning the Repository**

Clone the repository using the following command:

```bash
git clone https://github.com/iXelias/COMP4985-client-project.git
```

Navigate to the cloned directory:

```bash
cd COMP4985-client-project
```

## **Creating links to the repository**

Need to create links to D'Arcy's build system:

```bash
./create-links.sh <work/programming101dev/scripts/>
```

## **Running the generate-cmakelists.sh Script**

You will need to create the CMakeLists.txt file:

```bash
./generate-cmakelists.sh
```

## **Running the change-compiler.sh Script**

Tell CMake which compiler you want to use:

```bash
./change-compiler.sh -c <compiler>
```

To the see the list of possible compilers:

```bash
cat supported_cxx_compilers.txt
```

## **Building the program with GCC**

To build the program run:

```bash
gcc src/main.c src/ncurses_gui.c src/asn.c src/connection.c -o  client -lncurses -pthread
```


## **Running the program**

To run the program:

```bash
./client
```
