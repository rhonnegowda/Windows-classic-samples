﻿using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Reflection.Emit;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using Windows.Security.Cryptography;
using Windows.Security.DataProtection;
using Windows.Storage;
using Windows.Storage.Streams;
using Windows.UI.Xaml.Shapes;

namespace PDETestApp
{
    public partial class Form2 : Form
    {
        UserDataProtectionManager g_udpm;
        String g_selectedFolder = String.Empty;
        String g_selectedFile = String.Empty;
        public Form2()
        {
            InitializeComponent();
        }

        // Loads the Windows Form to exercise PDE API and instantiates the UserDataProtectionManager object
        private void Form2_load(object sender, EventArgs e)
        {
            g_udpm = UserDataProtectionManager.TryGetDefault();
            if (g_udpm == null)
            {
                LogLine("Personal Data Encryption is not supported or enabled. Restart this app to check again.");
            }
            else
            {
                LogLine("Personal Data Encryption is enabled.");
                g_udpm.DataAvailabilityStateChanged += M_udpm_DataAvailabilityStateChanged;
                LogCurrentDataAvailability();
                LogLine("Listening to DataAvailabilityStateChanged event");
            }
        }

        private void M_udpm_DataAvailabilityStateChanged(UserDataProtectionManager sender, UserDataAvailabilityStateChangedEventArgs args)
        {
            LogLine("DataAvailabilityStateChanged event received");
            LogCurrentDataAvailability();
        }

        // Logs PDE events
        private void LogLine(string msg)
        {
            if (InvokeRequired)
            {
                this.Invoke(new Action<string>(LogLine), new object[] { msg });
                return;
            }
            string ts = DateTime.Now.ToString("MM/dd/yy HH:mm:ss.fff");
            string newlog = "[" + ts + "] " + msg + "\r\n";
            textBox2.Text = newlog + textBox2.Text;
            textBox2.Select(bufferInputTextBox.TextLength, 0);
            textBox2.ScrollToCaret();
            Console.WriteLine(msg);
        }


        // Logs the availability of the data being protected by PDE
        private void LogCurrentDataAvailability()
        {
            bool l1Avl = g_udpm.IsContinuedDataAvailabilityExpected(UserDataAvailability.AfterFirstUnlock);
            bool l2Avl = g_udpm.IsContinuedDataAvailabilityExpected(UserDataAvailability.WhileUnlocked);
            LogLine("IsContinuedDataAvailabilityExpected AfterFirstUnlock: " + l1Avl + ", WhileUnlocked: " + l2Avl);
        }

        // Protects the File or Folder specified as the item to the given availability levels
        async void ProtectAndLog(IStorageItem item, UserDataAvailability level)
        {
            var protectResult = await g_udpm.ProtectStorageItemAsync(item, level);
            if (protectResult == UserDataStorageItemProtectionStatus.Succeeded)
            {
                LogLine("Protected " + item.Name + " to level " + level);
            }
            else
            {
                LogLine("Protection failed for " + item.Name + " to level " + level + ", status: " + protectResult);
            }
        }

        // Protects Folders recursively, 
        // NOTE: Protecting the folder first and then its contents ensures that contents added to that folder in the future will
        // get protected to the same level of protection as the folder
        async void ProtectFolderRecursively(StorageFolder folder, UserDataAvailability level)
        {
            // Protect the folder first so new files / folders after this point will
            // get protected automatically.
            ProtectAndLog(folder, level);

            // Protect all sub-folders recursively.
            var subFolders = await folder.GetFoldersAsync();
            foreach (var subFolder in subFolders)
            {
                ProtectFolderRecursively(subFolder, level);
            }

            // Finally protect all existing files in the folder.
            var files = await folder.GetFilesAsync();
            foreach (var file in files)
            {
                ProtectAndLog(file, level);
            }
        }

        // Unprotect the buffer that is PDE protected
        async void UnprotectBuffer(String protectbase64EncodedContent)
        {
            var protectedBuffer = CryptographicBuffer.DecodeFromBase64String(protectbase64EncodedContent);
            try
            {
                var result = await g_udpm.UnprotectBufferAsync(protectedBuffer);
                if (result.Status == UserDataBufferUnprotectStatus.Succeeded)
                {
                    String unprotectedText = CryptographicBuffer.ConvertBinaryToString(BinaryStringEncoding.Utf8, result.UnprotectedBuffer);
                    LogLine("Result of Unprotecting the buffer:" + unprotectedText
                        );
                    bufferOutputTextBox.Text = "";
                    bufferOutputTextBox.Text = unprotectedText;

                    LogLine("Status of Unprotectng the buffer:" + result.Status);
                }
                else
                {
                    LogLine("This protected buffer is currently unavailable for unprotection");
                }
            }
            catch(Exception ex) 
            {
                LogLine("Please verify first the input text provided for unprotecting!");
                LogLine(ex.ToString());
            }
        }

        // Protect the buffer to the level of protection specified
        async void ProtectBuffer(String text, UserDataAvailability level)
        {
            if (text.Length == 0)
            {
                return;
            }
            var buffer = CryptographicBuffer.ConvertStringToBinary(text, BinaryStringEncoding.Utf8);
            var protectedContent = await g_udpm.ProtectBufferAsync(buffer, level);
            String protectbase64EncodedContent = CryptographicBuffer.EncodeToBase64String(protectedContent);
            bufferOutputTextBox.Text = protectbase64EncodedContent;
            LogLine("Protected buffer: " + protectbase64EncodedContent);
        }

        // Button click event handler to protect folder to L1 level of protection
        private async void FolderL1_Click(object sender, EventArgs e)
        {
            if (g_selectedFolder.Length > 0)
            {
                StorageFolder folder = await StorageFolder.GetFolderFromPathAsync(g_selectedFolder);
                this.ProtectFolderRecursively(folder, UserDataAvailability.AfterFirstUnlock);
            }
        }

        // Button click event handler to protect folder to L2 level of protection
        private async void FolderL2_Click(object sender, EventArgs e)
        {
            if (g_selectedFolder.Length > 0)
            {
                StorageFolder folder = await StorageFolder.GetFolderFromPathAsync(g_selectedFolder);
                this.ProtectFolderRecursively(folder, UserDataAvailability.WhileUnlocked);
            }
        }

        // Button click event handler to unprotect folder and its contents
        private async void FolderUnprotect_Click(object sender, EventArgs e)
        {
            if (g_selectedFolder.Length > 0)
            {
                StorageFolder folder = await StorageFolder.GetFolderFromPathAsync(g_selectedFolder);
                this.ProtectFolderRecursively(folder, UserDataAvailability.Always);
            }
        }

        // Button click event handler to protect file to L1 level of protection
        private async void FileL1_Click(object sender, EventArgs e)
        {
            if (g_selectedFile.Length > 0)
            {
                IStorageItem item = await StorageFile.GetFileFromPathAsync(g_selectedFile);
                this.ProtectAndLog(item, UserDataAvailability.AfterFirstUnlock);
            }
        }

        // Button click event handler to protect file to L2 level of protection
        private async void FileL2_Click(object sender, EventArgs e)
        {
            if (g_selectedFile.Length > 0)
            {
                IStorageItem item = await StorageFile.GetFileFromPathAsync(g_selectedFile);
                this.ProtectAndLog(item, UserDataAvailability.WhileUnlocked);
            }
        }

        // Button click event handler to unprotect file
        private async void FileUnprotect_Click(object sender, EventArgs e)
        {
            if (g_selectedFile.Length > 0)
            {
                IStorageItem item = await StorageFile.GetFileFromPathAsync(g_selectedFile);
                this.ProtectAndLog(item, UserDataAvailability.Always);
            }
        }

        // Button click event handler to protect buffer to L1 level of protection
        private void BufferL1_Click(object sender, EventArgs e)
        {
            ProtectBuffer(bufferInputTextBox.Text, UserDataAvailability.AfterFirstUnlock);
        }

        // Button click event handler to protect buffer to L2 level of protection
        private void BufferL2_Click(object sender, EventArgs e)
        {
            ProtectBuffer(bufferInputTextBox.Text, UserDataAvailability.WhileUnlocked);
        }

        // Button click event handler to unprotect buffer
        private void BufferUnprotect_Click(object sender, EventArgs e)
        {
            if (bufferInputTextBox.Text.Length > 0)
            {
                UnprotectBuffer(bufferInputTextBox.Text);
            }
        }

        private void FolderSelectBrowse_Click(object sender, EventArgs e)
        {
            if (folderBrowserDialog.ShowDialog() == DialogResult.OK)
            {
                listViewSelectedFolder.Items.Clear();
                listViewSelectedFolder.Items.Add(folderBrowserDialog.SelectedPath.Trim());
                g_selectedFolder = folderBrowserDialog.SelectedPath;
            }
        }

        private void FileSelectBrowse_Click(object sender, EventArgs e)
        {
            if (fileBrowserDialog.ShowDialog() == DialogResult.OK)
            {
                listViewSelectedFile.Items.Clear();
                listViewSelectedFile.Items.Add(fileBrowserDialog.FileName.Trim());
                g_selectedFile = fileBrowserDialog.FileName;
            }
        }
    }
}
