################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
CPP_SRCS += \
../HashMap2.cpp \
../IpPacket.cpp \
../lookup3.cpp \
../main.cpp 

OBJS += \
./HashMap2.o \
./IpPacket.o \
./lookup3.o \
./main.o 

CPP_DEPS += \
./HashMap2.d \
./IpPacket.d \
./lookup3.d \
./main.d 


# Each subdirectory must supply rules for building sources it contributes
%.o: ../%.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C++ Compiler'
	g++ -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


