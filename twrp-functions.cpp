/*
	Copyright 2012 bigbiff/Dees_Troy TeamWin
	This file is part of TWRP/TeamWin Recovery Project.

	TWRP is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	TWRP is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with TWRP.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <unistd.h>
#include <vector>
#include <dirent.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <cctype>
#include <algorithm>
#include "twrp-functions.hpp"
#include "twcommon.h"
#include "gui/gui.hpp"
#ifndef BUILD_TWRPTAR_MAIN
#include "data.hpp"
#include "partitions.hpp"
#include "variables.h"
#include "bootloader_message_twrp/include/bootloader_message_twrp/bootloader_message.h"
#include "cutils/properties.h"
#include "cutils/android_reboot.h"
#include <sys/reboot.h>
#endif // ndef BUILD_TWRPTAR_MAIN
#ifndef TW_EXCLUDE_ENCRYPTED_BACKUPS
#include "openaes/inc/oaes_lib.h"
#endif
#include "set_metadata.h"

extern "C"
{
#include "libcrecovery/common.h"
}

static string tmp = Fox_tmp_dir;
static string split_img = tmp + "/split_img";
static string ramdisk = tmp + "/ramdisk";
static string tmp_boot = tmp + "/boot.img";

static string fstab1 = "/system/vendor/etc";
static string fstab2 = "/vendor/etc";

/* Execute a command */
int TWFunc::Exec_Cmd(const string & cmd, string & result)
{
  FILE *exec;
  char buffer[130];
  int ret = 0;
  exec = __popen(cmd.c_str(), "r");
  if (!exec)
    return -1;
  while (!feof(exec))
    {
      if (fgets(buffer, 128, exec) != NULL)
	{
	  result += buffer;
	}
    }
  ret = __pclose(exec);
  return ret;
}

int TWFunc::Exec_Cmd(const string & cmd)
{
  pid_t pid;
  int status;
  switch (pid = fork())
    {
    case -1:
      LOGERR("Exec_Cmd(): vfork failed: %d!\n", errno);
      return -1;
    case 0:			// child
      execl("/sbin/sh", "sh", "-c", cmd.c_str(), NULL);
      _exit(127);
      break;
    default:
      {
	if (TWFunc::Wait_For_Child(pid, &status, cmd) != 0)
	  return -1;
	else
	  return 0;
      }
    }
}

// Returns "file.name" from a full /path/to/file.name
string TWFunc::Get_Filename(const string & Path)
{
  size_t pos = Path.find_last_of("/");
  if (pos != string::npos)
    {
      string Filename;
      Filename = Path.substr(pos + 1, Path.size() - pos - 1);
      return Filename;
    }
  else
    return Path;
}

// Returns "/path/to/" from a full /path/to/file.name
string TWFunc::Get_Path(const string & Path)
{
  size_t pos = Path.find_last_of("/");
  if (pos != string::npos)
    {
      string Pathonly;
      Pathonly = Path.substr(0, pos + 1);
      return Pathonly;
    }
  else
    return Path;
}

// run a command and return its output
string TWFunc::Exec_With_Output(const string &cmd)
{
  string data;
  FILE *stream;
  const int max_buffer = 256;
  char buffer[max_buffer];
  string s = cmd + " 2>&1";

  stream = popen(s.c_str(), "r");
  if (stream)
    {
      while (!feof(stream))
	if (fgets(buffer, max_buffer, stream) != NULL)
	  data.append(buffer);
      pclose(stream);
    }
  return data;
}

int TWFunc::Wait_For_Child(pid_t pid, int *status, string Child_Name)
{
  pid_t rc_pid;

  rc_pid = waitpid(pid, status, 0);
  if (rc_pid > 0)
    {
      if (WIFSIGNALED(*status))
	{
	  gui_msg(Msg(msg::kError, "pid_signal={1} process ended with signal: {2}") (Child_Name) (WTERMSIG(*status)));	// Seg fault or some other non-graceful termination
	  return -1;
	}
      else if (WEXITSTATUS(*status) == 0)
	{
	  LOGINFO("%s process ended with RC=%d\n", Child_Name.c_str(), WEXITSTATUS(*status));	// Success
	}
      else
	{
	  gui_msg(Msg(msg::kError, "pid_error={1} process ended with ERROR: {2}") (Child_Name) (WEXITSTATUS(*status)));	// Graceful exit, but there was an error
	  return -1;
	}
    }
  else
    {				// no PID returned
      if (errno == ECHILD)
	LOGERR("%s no child process exist\n", Child_Name.c_str());
      else
	{
	  LOGERR("%s Unexpected error %d\n", Child_Name.c_str(), errno);
	  return -1;
	}
    }
  return 0;
}

int TWFunc::Wait_For_Child_Timeout(pid_t pid, int *status,
				   const string & Child_Name, int timeout)
{
  pid_t retpid = waitpid(pid, status, WNOHANG);
  for (; retpid == 0 && timeout; --timeout)
    {
      sleep(1);
      retpid = waitpid(pid, status, WNOHANG);
    }
  if (retpid == 0 && timeout == 0)
    {
      LOGERR("%s took too long, killing process\n", Child_Name.c_str());
      kill(pid, SIGKILL);
      int died = 0;
      for (timeout = 5; retpid == 0 && timeout; --timeout)
	{
	  sleep(1);
	  retpid = waitpid(pid, status, WNOHANG);
	}
      if (retpid)
	LOGINFO("Child process killed successfully\n");
      else
	LOGINFO
	  ("Child process took too long to kill, may be a zombie process\n");
      return -1;
    }
  else if (retpid > 0)
    {
      if (WIFSIGNALED(*status))
	{
	  gui_msg(Msg(msg::kError, "pid_signal={1} process ended with signal: {2}") (Child_Name) (WTERMSIG(*status)));	// Seg fault or some other non-graceful termination
	  return -1;
	}
    }
  else if (retpid < 0)
    {				// no PID returned
      if (errno == ECHILD)
	LOGERR("%s no child process exist\n", Child_Name.c_str());
      else
	{
	  LOGERR("%s Unexpected error %d\n", Child_Name.c_str(), errno);
	  return -1;
	}
    }
  return 0;
}

bool TWFunc::Path_Exists(string Path)
{
  struct stat st;
  if (stat(Path.c_str(), &st) != 0)
    return false;
  else
    return true;
}

Archive_Type TWFunc::Get_File_Type(string fn)
{
  string::size_type i = 0;
  int firstbyte = 0, secondbyte = 0;
  char header[3];

  ifstream f;
  f.open(fn.c_str(), ios::in | ios::binary);
  f.get(header, 3);
  f.close();
  firstbyte = header[i] & 0xff;
  secondbyte = header[++i] & 0xff;

  if (firstbyte == 0x1f && secondbyte == 0x8b)
    return COMPRESSED;
  else if (firstbyte == 0x4f && secondbyte == 0x41)
    return ENCRYPTED;
  return UNCOMPRESSED;		// default
}

int TWFunc::Try_Decrypting_File(string fn, string password)
{
#ifndef TW_EXCLUDE_ENCRYPTED_BACKUPS
  OAES_CTX *ctx = NULL;
  uint8_t _key_data[32] = "";
  FILE *f;
  uint8_t buffer[4096];
  uint8_t *buffer_out = NULL;
  uint8_t *ptr = NULL;
  size_t read_len = 0, out_len = 0;
  int firstbyte = 0, secondbyte = 0;
  size_t _j = 0;
  size_t _key_data_len = 0;

  // mostly kanged from OpenAES oaes.c
  for (_j = 0; _j < 32; _j++)
    _key_data[_j] = _j + 1;
  _key_data_len = password.size();
  if (16 >= _key_data_len)
    _key_data_len = 16;
  else if (24 >= _key_data_len)
    _key_data_len = 24;
  else
    _key_data_len = 32;
  memcpy(_key_data, password.c_str(), password.size());

  ctx = oaes_alloc();
  if (ctx == NULL)
    {
      LOGERR("Failed to allocate OAES\n");
      return -1;
    }

  oaes_key_import_data(ctx, _key_data, _key_data_len);

  f = fopen(fn.c_str(), "rb");
  if (f == NULL)
    {
      LOGERR("Failed to open '%s' to try decrypt: %s\n", fn.c_str(),
	     strerror(errno));
      oaes_free(&ctx);
      return -1;
    }
  read_len = fread(buffer, sizeof(uint8_t), 4096, f);
  if (read_len <= 0)
    {
      LOGERR("Read size during try decrypt failed: %s\n", strerror(errno));
      fclose(f);
      oaes_free(&ctx);
      return -1;
    }
  if (oaes_decrypt(ctx, buffer, read_len, NULL, &out_len) != OAES_RET_SUCCESS)
    {
      LOGERR
	("Error: Failed to retrieve required buffer size for trying decryption.\n");
      fclose(f);
      oaes_free(&ctx);
      return -1;
    }
  buffer_out = (uint8_t *) calloc(out_len, sizeof(char));
  if (buffer_out == NULL)
    {
      LOGERR("Failed to allocate output buffer for try decrypt.\n");
      fclose(f);
      oaes_free(&ctx);
      return -1;
    }
  if (oaes_decrypt(ctx, buffer, read_len, buffer_out, &out_len) !=
      OAES_RET_SUCCESS)
    {
      LOGERR("Failed to decrypt file '%s'\n", fn.c_str());
      fclose(f);
      free(buffer_out);
      oaes_free(&ctx);
      return 0;
    }
  fclose(f);
  oaes_free(&ctx);
  if (out_len < 2)
    {
      LOGINFO("Successfully decrypted '%s' but read length too small.\n",
	      fn.c_str());
      free(buffer_out);
      return 1;			// Decrypted successfully
    }
  ptr = buffer_out;
  firstbyte = *ptr & 0xff;
  ptr++;
  secondbyte = *ptr & 0xff;
  if (firstbyte == 0x1f && secondbyte == 0x8b)
    {
      LOGINFO("Successfully decrypted '%s' and file is compressed.\n",
	      fn.c_str());
      free(buffer_out);
      return 3;			// Compressed
    }

  if (out_len >= 262)
    {
      ptr = buffer_out + 257;
      if (strncmp((char *) ptr, "ustar", 5) == 0)
	{
	  LOGINFO("Successfully decrypted '%s' and file is tar format.\n",
		  fn.c_str());
	  free(buffer_out);
	  return 2;		// Tar
	}
    }
  free(buffer_out);
  LOGINFO("No errors decrypting '%s' but no known file format.\n",
	  fn.c_str());
  return 1;			// Decrypted successfully
#else
  LOGERR("Encrypted backup support not included.\n");
  return -1;
#endif
}

unsigned long TWFunc::Get_File_Size(const string & Path)
{
  struct stat st;

  if (stat(Path.c_str(), &st) != 0)
    return 0;
  return st.st_size;
}

std::string TWFunc::Remove_Trailing_Slashes(const std::string & path,
					    bool leaveLast)
{
  std::string res;
  size_t last_idx = 0, idx = 0;

  while (last_idx != std::string::npos)
    {
      if (last_idx != 0)
	res += '/';

      idx = path.find_first_of('/', last_idx);
      if (idx == std::string::npos)
	{
	  res += path.substr(last_idx, idx);
	  break;
	}

      res += path.substr(last_idx, idx - last_idx);
      last_idx = path.find_first_not_of('/', idx);
    }

  if (leaveLast)
    res += '/';
  return res;
}

void TWFunc::Strip_Quotes(char *&str)
{
  if (strlen(str) > 0 && str[0] == '\"')
    str++;
  if (strlen(str) > 0 && str[strlen(str) - 1] == '\"')
    str[strlen(str) - 1] = 0;
}

vector < string > TWFunc::split_string(const string & in, char del,
				       bool skip_empty)
{
  vector < string > res;

  if (in.empty() || del == '\0')
    return res;

  string field;
  istringstream f(in);
  if (del == '\n')
    {
      while (getline(f, field))
	{
	  if (field.empty() && skip_empty)
	    continue;
	  res.push_back(field);
	}
    }
  else
    {
      while (getline(f, field, del))
	{
	  if (field.empty() && skip_empty)
	    continue;
	  res.push_back(field);
	}
    }
  return res;
}

timespec TWFunc::timespec_diff(timespec & start, timespec & end)
{
  timespec temp;
  if ((end.tv_nsec - start.tv_nsec) < 0)
    {
      temp.tv_sec = end.tv_sec - start.tv_sec - 1;
      temp.tv_nsec = 1000000000 + end.tv_nsec - start.tv_nsec;
    }
  else
    {
      temp.tv_sec = end.tv_sec - start.tv_sec;
      temp.tv_nsec = end.tv_nsec - start.tv_nsec;
    }
  return temp;
}

int32_t TWFunc::timespec_diff_ms(timespec & start, timespec & end)
{
  return ((end.tv_sec * 1000) + end.tv_nsec / 1000000) -
    ((start.tv_sec * 1000) + start.tv_nsec / 1000000);
}

#ifndef BUILD_TWRPTAR_MAIN

// Returns "/path" from a full /path/to/file.name
string TWFunc::Get_Root_Path(const string & Path)
{
  string Local_Path = Path;

  // Make sure that we have a leading slash
  if (Local_Path.substr(0, 1) != "/")
    Local_Path = "/" + Local_Path;

  // Trim the path to get the root path only
  size_t position = Local_Path.find("/", 2);
  if (position != string::npos)
    {
      Local_Path.resize(position);
    }
  return Local_Path;
}

void TWFunc::install_htc_dumlock(void)
{
  int need_libs = 0;

  if (!PartitionManager.Mount_By_Path("/system", true))
    return;

  if (!PartitionManager.Mount_By_Path("/data", true))
    return;

  gui_msg("install_dumlock=Installing HTC Dumlock to system...");
  copy_file(TWHTCD_PATH "htcdumlocksys", "/system/bin/htcdumlock", 0755);
  if (!Path_Exists("/system/bin/flash_image"))
    {
      LOGINFO("Installing flash_image...\n");
      copy_file(TWHTCD_PATH "flash_imagesys", "/system/bin/flash_image",
		0755);
      need_libs = 1;
    }
  else
    LOGINFO("flash_image is already installed, skipping...\n");
  if (!Path_Exists("/system/bin/dump_image"))
    {
      LOGINFO("Installing dump_image...\n");
      copy_file(TWHTCD_PATH "dump_imagesys", "/system/bin/dump_image", 0755);
      need_libs = 1;
    }
  else
    LOGINFO("dump_image is already installed, skipping...\n");
  if (need_libs)
    {
      LOGINFO("Installing libs needed for flash_image and dump_image...\n");
      copy_file(TWHTCD_PATH "libbmlutils.so", "/system/lib/libbmlutils.so",
		0644);
      copy_file(TWHTCD_PATH "libflashutils.so",
		"/system/lib/libflashutils.so", 0644);
      copy_file(TWHTCD_PATH "libmmcutils.so", "/system/lib/libmmcutils.so",
		0644);
      copy_file(TWHTCD_PATH "libmtdutils.so", "/system/lib/libmtdutils.so",
		0644);
    }
  LOGINFO("Installing HTC Dumlock app...\n");
  mkdir("/data/app", 0777);
  unlink("/data/app/com.teamwin.htcdumlock*");
  copy_file(TWHTCD_PATH "HTCDumlock.apk",
	    "/data/app/com.teamwin.htcdumlock.apk", 0777);
  sync();
  gui_msg("done=Done.");
}


void TWFunc::htc_dumlock_restore_original_boot(void)
{
  if (!PartitionManager.Mount_By_Path("/sdcard", true))
    return;

  gui_msg("dumlock_restore=Restoring original boot...");
  Exec_Cmd("htcdumlock restore");
  gui_msg("done=Done.");
}


void TWFunc::htc_dumlock_reflash_recovery_to_boot(void)
{
  if (!PartitionManager.Mount_By_Path("/sdcard", true))
    return;
  gui_msg("dumlock_reflash=Reflashing recovery to boot...");
  Exec_Cmd("htcdumlock recovery noreboot");
  gui_msg("done=Done.");
}


int TWFunc::Recursive_Mkdir(string Path)
{
  std::vector < std::string > parts = Split_String(Path, "/", true);
  std::string cur_path;
  for (size_t i = 0; i < parts.size(); ++i)
    {
      cur_path += "/" + parts[i];
      if (!TWFunc::Path_Exists(cur_path))
	{
	  if (mkdir(cur_path.c_str(), 0777))
	    {
	      gui_msg(Msg
		      (msg::kError,
		       "create_folder_strerr=Can not create '{1}' folder ({2}).")
		      (cur_path) (strerror(errno)));
	      return false;
	    }
	  else
	    {
	      tw_set_default_metadata(cur_path.c_str());
	    }
	}
    }
  return true;
}


void TWFunc::GUI_Operation_Text(string Read_Value, string Default_Text)
{
  string Display_Text;

  DataManager::GetValue(Read_Value, Display_Text);
  if (Display_Text.empty())
    Display_Text = Default_Text;

  DataManager::SetValue("tw_operation", Display_Text);
  DataManager::SetValue("tw_partition", "");
}


void TWFunc::GUI_Operation_Text(string Read_Value, string Partition_Name,
				string Default_Text)
{
  string Display_Text;

  DataManager::GetValue(Read_Value, Display_Text);
  if (Display_Text.empty())
    Display_Text = Default_Text;

  DataManager::SetValue("tw_operation", Display_Text);
  DataManager::SetValue("tw_partition", Partition_Name);
}


void TWFunc::Copy_Log(string Source, string Destination)
{
  PartitionManager.Mount_By_Path(Destination, false);
  FILE *destination_log = fopen(Destination.c_str(), "a");
  if (destination_log == NULL)
    {
      LOGERR("TWFunc::Copy_Log -- Can't open destination log file: '%s'\n",
	     Destination.c_str());
    }
  else
    {
      FILE *source_log = fopen(Source.c_str(), "r");
      if (source_log != NULL)
	{
	  fseek(source_log, Log_Offset, SEEK_SET);
	  char buffer[4096];
	  while (fgets(buffer, sizeof(buffer), source_log))
	    fputs(buffer, destination_log);	// Buffered write of log file
	  Log_Offset = ftell(source_log);
	  fflush(source_log);
	  fclose(source_log);
	}
      fflush(destination_log);
      fclose(destination_log);
    }
}


void TWFunc::Update_Log_File(void)
{
  // Copy logs to cache so the system can find out what happened.
  if (PartitionManager.Mount_By_Path("/cache", false))
    {
      if (!TWFunc::Path_Exists("/cache/recovery/."))
	{
	  LOGINFO("Recreating /cache/recovery folder.\n");
	  if (mkdir("/cache/recovery", S_IRWXU | S_IRWXG | S_IWGRP | S_IXGRP)
	      != 0)
	    LOGINFO("Unable to create /cache/recovery folder.\n");
	}
      Copy_Log(TMP_LOG_FILE, "/cache/recovery/log");
      copy_file("/cache/recovery/log", "/cache/recovery/last_log", 600);
      chown("/cache/recovery/log", 1000, 1000);
      chmod("/cache/recovery/log", 0600);
      chmod("/cache/recovery/last_log", 0640);
    }
  else if (PartitionManager.Mount_By_Path("/data", false)
	   && TWFunc::Path_Exists("/data/cache/recovery/."))
    {
      Copy_Log(TMP_LOG_FILE, "/data/cache/recovery/log");
      copy_file("/data/cache/recovery/log", "/data/cache/recovery/last_log",
		600);
      chown("/data/cache/recovery/log", 1000, 1000);
      chmod("/data/cache/recovery/log", 0600);
      chmod("/data/cache/recovery/last_log", 0640);
    }
  else
    {
      LOGINFO
	("Failed to mount /cache or find /data/cache for TWFunc::Update_Log_File\n");
    }

  // Reset bootloader message
  TWPartition *Part = PartitionManager.Find_Partition_By_Path("/misc");
  if (Part != NULL)
    {
      std::string err;
      if (!clear_bootloader_message((void *) &err))
	{
	  if (err == "no misc device set")
	    {
	      LOGINFO("%s\n", err.c_str());
	    }
	  else
	    {
	      LOGERR("%s\n", err.c_str());
	    }
	}
    }

  if (PartitionManager.Mount_By_Path("/cache", false))
    {
      if (unlink("/cache/recovery/command") && errno != ENOENT)
	{
	  LOGINFO("Can't unlink %s\n", "/cache/recovery/command");
	}
    }

  sync();
}

void TWFunc::Update_Intent_File(string Intent)
{
  if (PartitionManager.Mount_By_Path("/cache", false) && !Intent.empty())
    {
      TWFunc::write_to_file("/cache/recovery/intent", Intent);
    }
}


// reboot: Reboot the system. Return -1 on error, no return on success
int TWFunc::tw_reboot(RebootCommand command)
{
  int DoDeactivate = 0;
  DataManager::Flush();
  Update_Log_File();
  
  // Always force a sync before we reboot
  sync();

  // DJ9 - if we haven't called Deactivation_Process before, check whether to call it now 
  // This code is currently disabled - Fox_AutoDeactivate_OnReboot is never set to 1
  if ((Fox_AutoDeactivate_OnReboot == 1) && (Fox_IsDeactivation_Process_Called == 0))
    {
      if ( /*(Fox_Current_ROM_IsMIUI == 1) ||*/ 
	   (DataManager::GetIntValue(RW_DISABLE_DM_VERITY) == 1)       
	   || (DataManager::GetIntValue(RW_DISABLE_FORCED_ENCRYPTION) == 1)
         ) 
        { 
           DoDeactivate = 1; 
        }
    }    
  // DJ9
   
  switch (command)
    {
    case rb_current:
    case rb_system:
      if (DoDeactivate == 1) { Deactivation_Process(); } // DJ9  
      Update_Intent_File("s");
      sync();
#ifdef ANDROID_RB_PROPERTY
      return property_set(ANDROID_RB_PROPERTY, "reboot,");
#elif defined(ANDROID_RB_RESTART)
      return android_reboot(ANDROID_RB_RESTART, 0, 0);
#else
      return reboot(RB_AUTOBOOT);
#endif
    case rb_recovery:
      if (DoDeactivate == 1){ Deactivation_Process(); } // DJ9  
#ifdef ANDROID_RB_PROPERTY
      return property_set(ANDROID_RB_PROPERTY, "reboot,recovery");
#else
      return __reboot(LINUX_REBOOT_MAGIC1, LINUX_REBOOT_MAGIC2,
		      LINUX_REBOOT_CMD_RESTART2, (void *) "recovery");
#endif
    case rb_bootloader:
#ifdef ANDROID_RB_PROPERTY
      return property_set(ANDROID_RB_PROPERTY, "reboot,bootloader");
#else
      return __reboot(LINUX_REBOOT_MAGIC1, LINUX_REBOOT_MAGIC2,
		      LINUX_REBOOT_CMD_RESTART2, (void *) "bootloader");
#endif
    case rb_poweroff:
#ifdef ANDROID_RB_PROPERTY
      return property_set(ANDROID_RB_PROPERTY, "shutdown,");
#elif defined(ANDROID_RB_POWEROFF)
      return android_reboot(ANDROID_RB_POWEROFF, 0, 0);
#else
      return reboot(RB_POWER_OFF);
#endif
    case rb_download:
#ifdef ANDROID_RB_PROPERTY
      return property_set(ANDROID_RB_PROPERTY, "reboot,download");
#else
      return __reboot(LINUX_REBOOT_MAGIC1, LINUX_REBOOT_MAGIC2,
		      LINUX_REBOOT_CMD_RESTART2, (void *) "download");
#endif
    default:
      return -1;
    }
  return -1;
}

void TWFunc::check_and_run_script(const char *script_file,
				  const char *display_name)
{
  // Check for and run startup script if script exists
  struct stat st;
  if (stat(script_file, &st) == 0)
    {
      chmod(script_file, S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);
      TWFunc::Exec_Cmd(script_file);
    }
}

int TWFunc::removeDir(const string path, bool skipParent)
{
  DIR *d = opendir(path.c_str());
  int r = 0;
  string new_path;

  if (d == NULL)
    {
      gui_msg(Msg
	      (msg::kError,
	       "error_opening_strerr=Error opening: '{1}' ({2})") (path)
	      (strerror(errno)));
      return -1;
    }

  if (d)
    {
      struct dirent *p;
      while (!r && (p = readdir(d)))
	{
	  if (!strcmp(p->d_name, ".") || !strcmp(p->d_name, ".."))
	    continue;
	  new_path = path + "/";
	  new_path.append(p->d_name);
	  if (p->d_type == DT_DIR)
	    {
	      r = removeDir(new_path, true);
	      if (!r)
		{
		  if (p->d_type == DT_DIR)
		    r = rmdir(new_path.c_str());
		  else
		    LOGINFO("Unable to removeDir '%s': %s\n",
			    new_path.c_str(), strerror(errno));
		}
	    }
	  else if (p->d_type == DT_REG || p->d_type == DT_LNK
		   || p->d_type == DT_FIFO || p->d_type == DT_SOCK)
	    {
	      r = unlink(new_path.c_str());
	      if (r != 0)
		{
		  LOGINFO("Unable to unlink '%s: %s'\n", new_path.c_str(),
			  strerror(errno));
		}
	    }
	}
      closedir(d);

      if (!r)
	{
	  if (skipParent)
	    return 0;
	  else
	    r = rmdir(path.c_str());
	}
    }
  return r;
}

int TWFunc::copy_file(string src, string dst, int mode)
{

  ifstream srcfile(src.c_str(), ios::binary);
  ofstream dstfile(dst.c_str(), ios::binary);
  dstfile << srcfile.rdbuf();
  srcfile.close();
  dstfile.close();
  if (chmod(dst.c_str(), mode) != 0)
    return -1;
  return 0;
}

unsigned int TWFunc::Get_D_Type_From_Stat(string Path)
{
  struct stat st;

  stat(Path.c_str(), &st);
  if (st.st_mode & S_IFDIR)
    return DT_DIR;
  else if (st.st_mode & S_IFBLK)
    return DT_BLK;
  else if (st.st_mode & S_IFCHR)
    return DT_CHR;
  else if (st.st_mode & S_IFIFO)
    return DT_FIFO;
  else if (st.st_mode & S_IFLNK)
    return DT_LNK;
  else if (st.st_mode & S_IFREG)
    return DT_REG;
  else if (st.st_mode & S_IFSOCK)
    return DT_SOCK;
  return DT_UNKNOWN;
}

int TWFunc::read_file(string fn, string & results)
{
  ifstream file;
  file.open(fn.c_str(), ios::in);

  if (file.is_open())
    {
      file >> results;
      file.close();
      return 0;
    }

  LOGINFO("Cannot find file %s\n", fn.c_str());
  return -1;
}

int TWFunc::read_file(string fn, vector < string > &results)
{
  ifstream file;
  string line;
  file.open(fn.c_str(), ios::in);
  if (file.is_open())
    {
      while (getline(file, line))
	results.push_back(line);
      file.close();
      return 0;
    }
  LOGINFO("Cannot find file %s\n", fn.c_str());
  return -1;
}

int TWFunc::read_file(string fn, uint64_t & results)
{
  ifstream file;
  file.open(fn.c_str(), ios::in);

  if (file.is_open())
    {
      file >> results;
      file.close();
      return 0;
    }

  LOGINFO("Cannot find file %s\n", fn.c_str());
  return -1;
}

int TWFunc::write_to_file(const string & fn, const string & line)
{
  FILE *file;
  file = fopen(fn.c_str(), "w");
  if (file != NULL)
    {
      fwrite(line.c_str(), line.size(), 1, file);
      fclose(file);
      return 0;
    }
  LOGINFO("Cannot find file %s\n", fn.c_str());
  return -1;
}

bool TWFunc::Try_Decrypting_Backup(string Restore_Path, string Password) {
	DIR* d;

  string Filename;
  Restore_Path += "/";
  d = opendir(Restore_Path.c_str());
  if (d == NULL)
    {
      gui_msg(Msg
	      (msg::kError,
	       "error_opening_strerr=Error opening: '{1}' ({2})")
	      (Restore_Path) (strerror(errno)));
      return false;
    }

  struct dirent *de;
  while ((de = readdir(d)) != NULL)
    {
      Filename = Restore_Path;
      Filename += de->d_name;
      if (TWFunc::Get_File_Type(Filename) == ENCRYPTED)
	{
	  if (TWFunc::Try_Decrypting_File(Filename, Password) < 2)
	    {
	      DataManager::SetValue("tw_restore_password", "");	// Clear the bad password
	      DataManager::SetValue("tw_restore_display", "");	// Also clear the display mask
	      closedir(d);
	      return false;
	    }
	}
    }
  closedir(d);
  return true;
}

string TWFunc::Get_Current_Date()
{
  string Current_Date;
  time_t seconds = time(0);
  struct tm *t = localtime(&seconds);
  char timestamp[255];
  sprintf(timestamp, "%04d-%02d-%02d--%02d-%02d-%02d", t->tm_year + 1900,
	  t->tm_mon + 1, t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec);
  Current_Date = timestamp;
  return Current_Date;
}

string TWFunc::System_Property_Get(string Prop_Name)
{
  bool mount_state = PartitionManager.Is_Mounted_By_Path("/system");
  std::vector < string > buildprop;
  string propvalue;
  if (!PartitionManager.Mount_By_Path("/system", true))
    return propvalue;
  string prop_file = "/system/build.prop";
  if (!TWFunc::Path_Exists(prop_file))
    prop_file = "/system/system/build.prop";	// for devices with system as a root file system (e.g. Pixel)
  if (TWFunc::read_file(prop_file, buildprop) != 0)
    {
      LOGINFO("Unable to open /system/build.prop for getting '%s'.\n",
	      Prop_Name.c_str());
      DataManager::SetValue(TW_BACKUP_NAME, Get_Current_Date());
      if (!mount_state)
	PartitionManager.UnMount_By_Path("/system", false);
      return propvalue;
    }
  int line_count = buildprop.size();
  int index;
  size_t start_pos = 0, end_pos;
  string propname;
  for (index = 0; index < line_count; index++)
    {
      end_pos = buildprop.at(index).find("=", start_pos);
      propname = buildprop.at(index).substr(start_pos, end_pos);
      if (propname == Prop_Name)
	{
	  propvalue =
	    buildprop.at(index).substr(end_pos + 1,
				       buildprop.at(index).size());
	  if (!mount_state)
	    PartitionManager.UnMount_By_Path("/system", false);
	  return propvalue;
	}
    }
  if (!mount_state)
    PartitionManager.UnMount_By_Path("/system", false);
  return propvalue;
}

string TWFunc::File_Property_Get(string File_Path, string Prop_Name)
{
  std::vector < string > buildprop;
  string propvalue;
  string prop_file = File_Path;
  if (TWFunc::read_file(prop_file, buildprop) != 0)
    {
      return propvalue;
    }
  int line_count = buildprop.size();
  int index;
  size_t start_pos = 0, end_pos;
  string propname;
  for (index = 0; index < line_count; index++)
    {
      end_pos = buildprop.at(index).find("=", start_pos);
      propname = buildprop.at(index).substr(start_pos, end_pos);
      if (propname == Prop_Name)
	{
	  propvalue =
	    buildprop.at(index).substr(end_pos + 1,
				       buildprop.at(index).size());
	  return propvalue;
	}
    }
  return propvalue;
}


void TWFunc::Auto_Generate_Backup_Name()
{
  string propvalue = System_Property_Get("ro.build.display.id");
  if (propvalue.empty())
    {
      DataManager::SetValue(TW_BACKUP_NAME, Get_Current_Date());
      return;
    }
  else
    {
      //remove periods from build display so it doesn't confuse the extension code
      propvalue.erase(remove(propvalue.begin(), propvalue.end(), '.'),
		      propvalue.end());
    }
  string Backup_Name = Get_Current_Date();
  Backup_Name += "_" + propvalue;
  if (Backup_Name.size() > MAX_BACKUP_NAME_LEN)
    Backup_Name.resize(MAX_BACKUP_NAME_LEN);
  // Trailing spaces cause problems on some file systems, so remove them
  string space_check, space = " ";
  space_check = Backup_Name.substr(Backup_Name.size() - 1, 1);
  while (space_check == space)
    {
      Backup_Name.resize(Backup_Name.size() - 1);
      space_check = Backup_Name.substr(Backup_Name.size() - 1, 1);
    }
  replace(Backup_Name.begin(), Backup_Name.end(), ' ', '_');
  DataManager::SetValue(TW_BACKUP_NAME, Backup_Name);
  if (PartitionManager.Check_Backup_Name(false) != 0)
    {
      LOGINFO
	("Auto generated backup name '%s' contains invalid characters, using date instead.\n",
	 Backup_Name.c_str());
      DataManager::SetValue(TW_BACKUP_NAME, Get_Current_Date());
    }
}

void TWFunc::Fixup_Time_On_Boot(const string & time_paths)
{
#ifdef QCOM_RTC_FIX
  static bool fixed = false;
  
  if (fixed) // i.e., we have sorted out the date/time issue properly
   {
    return;
   }

  LOGINFO("TWFunc::Fixup_Time: Pre-fix date and time: %s\n", TWFunc::Get_Current_Date().c_str());
  
  struct timeval tv;
  uint64_t offset = 0;
  uint64_t drift = 0;
  int store = 0;
  unsigned long long stored_drift = 0;
  const uint64_t min_offset = 1526913615; // minimum offset = Mon May 21 15:40:17 BST 2018
  std::string sepoch = "/sys/class/rtc/rtc0/since_epoch";

  if (TWFunc::read_file(sepoch, offset) == 0)
    {

      LOGINFO("TWFunc::Fixup_Time: Setting time offset from file %s\n", sepoch.c_str());

      // DJ9
      if (offset < 1261440000) // bad RTC (less than 41 years since epoch!)
      {  
	 LOGINFO ("TWFunc::Fixup_Time: Your RTC is broken (the alleged date/time is %s)\n", TWFunc::Get_Current_Date().c_str());
	 
	 // try to correct 	 
	 if (DataManager::GetValue("fox_epoch_drift", stored_drift) < 0) // read from .foxs
	 	stored_drift = 0;
	 
	 if (TWFunc::read_file (epoch_drift_file, drift) != 0) // read from epoch drift file
	 	drift = 0;
	 
	 // what have we succeeded in reading?
         if ((drift > 0) || (stored_drift > 0)) 
         {
            if ((stored_drift > 0) && (drift == 0)) // we only got drift from .foxs
                {
           	  drift = stored_drift;
           	  LOGINFO ("TWFunc::Fixup_Time: Using drift value (%lu) stored in .foxs\n", drift);
                } 
            else 
            {   
           	 if ((stored_drift > 0) && (drift > 0)) // we got two values
              	 {
                    if (stored_drift != drift) // let drift override stored_drift, and save drift
                    {
                        store = 1; 
                    } 
                    LOGINFO ("TWFunc::Fixup_Time: using drift value (%lu) stored in %s\n", drift, epoch_drift_file.c_str());
              	 } 
              	 else // either both are 0, or stored_drift is 0
              	 {
              	    if (drift > 0) // then stored_drift must be 0
              	    {
                        LOGINFO ("TWFunc::Fixup_Time: using drift value (%lu) stored in %s\n", drift, epoch_drift_file.c_str());              	    
              	    	store = 1;
              	    }
              	 }             
             }
             
	   // now see if we have a sensible value            
           if (drift > 1369180500) // ignore drifts from earlier than Tuesday, May 21, 2013 11:55:00 PM
           { 
              offset += drift; 
              LOGINFO ("TWFunc::Fixup_Time: Compensated for drift by %lu \n", drift);
              DataManager::SetValue("tw_qcom_ats_offset", (unsigned long long) offset, 1); // store this new offset
              
              if (store == 1) // we haven't already stored the drift in .foxs
              	DataManager::SetValue("fox_epoch_drift", (unsigned long long) drift, 1); // store the drift value
           }
           
         } // if (drift > 0) || (stored_drift > 0)
      }	// if offset
      // DJ9      
      
      tv.tv_sec = offset;
      tv.tv_usec = 0;
      settimeofday(&tv, NULL);
      gettimeofday(&tv, NULL);
      
      offset = tv.tv_sec;  // this and the next line to get rid of warnings
      if (offset > min_offset)
	{
	  LOGINFO("TWFunc::Fixup_Time: Date and time corrected: %s\n", TWFunc::Get_Current_Date().c_str());
	  fixed = true;
	  return;
	} 
	else 
	{
      	  LOGINFO("TWFunc::Fixup_Time: Wrong date and time epoch in %s\n", sepoch.c_str());
	}
    }
  else
    {
      LOGINFO("TWFunc::Fixup_Time: opening %s failed\n", sepoch.c_str());
    }

  LOGINFO("TWFunc::Fixup_Time: will attempt to use the ats files now.\n");

  // Devices with Qualcomm Snapdragon 800 do some shenanigans with RTC.
  // They never set it, it just ticks forward from 1970-01-01 00:00,
  // and then they have files /data/system/time/ats_* with 64bit offset
  // in miliseconds which, when added to the RTC, gives the correct time.
  // So, the time is: (offset_from_ats + value_from_RTC)
  // There are multiple ats files, they are for different systems? Bases?
  // Like, ats_1 is for modem and ats_2 is for TOD (time of day?).
  // Look at file time_genoff.h in CodeAurora, qcom-opensource/time-services

  std::vector < std::string > paths;	// space separated list of paths
  if (time_paths.empty())
    {
      paths = Split_String("/data/system/time/ /data/time/", " ");
      if (!PartitionManager.Mount_By_Path("/data", false))
	return;
    }
  else
    {
      // When specific path(s) are used, Fixup_Time needs those
      // partitions to already be mounted!
      paths = Split_String(time_paths, " ");
    }

  FILE *f;
  offset = 0;
  struct dirent *dt;
  std::string ats_path;

  // Prefer ats_2, it seems to be the one we want according to logcat on hammerhead
  // - it is the one for ATS_TOD (time of day?).
  // However, I never saw a device where the offset differs between ats files.
  for (size_t i = 0; i < paths.size(); ++i)
    {
      DIR *d = opendir(paths[i].c_str());
      if (!d)
	continue;

      while ((dt = readdir(d)))
	{
	  if (dt->d_type != DT_REG || strncmp(dt->d_name, "ats_", 4) != 0)
	    continue;

	  if (ats_path.empty() || strcmp(dt->d_name, "ats_2") == 0)
	    ats_path = paths[i] + dt->d_name;
	}

      closedir(d);
    }

  if (ats_path.empty())
    {
      LOGINFO("TWFunc::Fixup_Time: no ats files found, leaving untouched!\n");
    }
  else if ((f = fopen(ats_path.c_str(), "r")) == NULL)
    {
      LOGINFO("TWFunc::Fixup_Time: failed to open file %s\n",
	      ats_path.c_str());
    }
  else if (fread(&offset, sizeof(offset), 1, f) != 1)
    {
      LOGINFO("TWFunc::Fixup_Time: failed load uint64 from file %s\n",
	      ats_path.c_str());
      fclose(f);
    }
  else
    {
      fclose(f);

      LOGINFO
	("TWFunc::Fixup_Time: Setting time offset from file %s, offset %llu\n",
	 ats_path.c_str(), (unsigned long long) offset);
      DataManager::SetValue("tw_qcom_ats_offset", (unsigned long long) offset, 1);
      fixed = true;
    }

  if (!fixed)
    {
      // Failed to get offset from ats file, check twrp settings
      unsigned long long value;
      if (DataManager::GetValue("tw_qcom_ats_offset", value) < 0)
	{
	  return;
	}
      else
	{
	  // Do not consider the settings file as a definitive answer, keep fixed=false so next run will try ats files again
	  offset = (uint64_t) value;
	  LOGINFO
	    ("TWFunc::Fixup_Time: Setting time offset from twrp setting file, offset %llu\n",
	     (unsigned long long) offset);
	     // DJ9
	        tv.tv_sec = offset;
      		tv.tv_usec = 0;
      		settimeofday(&tv, NULL);
      		gettimeofday(&tv, NULL);
      		return;
      	     // DJ9
	}
    }

  gettimeofday(&tv, NULL);

  tv.tv_sec += offset / 1000;
  
#ifdef TW_CLOCK_OFFSET
// Some devices are even quirkier and have ats files that are offset from the actual time
	tv.tv_sec = tv.tv_sec + TW_CLOCK_OFFSET;
#endif
  
  tv.tv_usec += (offset % 1000) * 1000;

  while (tv.tv_usec >= 1000000)
    {
      ++tv.tv_sec;
      tv.tv_usec -= 1000000;
    }

  settimeofday(&tv, NULL);

// DJ9 last check for sensible offset
    if (offset < min_offset) // let's try something else 
    {
      LOGINFO("TWFunc::Fixup_Time: trying for the last time!\n");
      tv.tv_sec = min_offset;
      tv.tv_usec = 0;   
      settimeofday(&tv, NULL);
      gettimeofday(&tv, NULL);
    }
// DJ9

  LOGINFO("TWFunc::Fixup_Time: Date and time corrected: %s\n", TWFunc::Get_Current_Date().c_str());
#endif
}

std::vector < std::string > TWFunc::Split_String(const std::string & str,
						 const std::
						 string & delimiter,
						 bool removeEmpty)
{
  std::vector < std::string > res;
  size_t idx = 0, idx_last = 0;

  while (idx < str.size())
    {
      idx = str.find_first_of(delimiter, idx_last);
      if (idx == std::string::npos)
	idx = str.size();

      if (idx - idx_last != 0 || !removeEmpty)
	res.push_back(str.substr(idx_last, idx - idx_last));

      idx_last = idx + delimiter.size();
    }

  return res;
}

bool TWFunc::Create_Dir_Recursive(const std::string & path, mode_t mode,
				  uid_t uid, gid_t gid)
{
  std::vector < std::string > parts = Split_String(path, "/");
  std::string cur_path;
  struct stat info;
  for (size_t i = 0; i < parts.size(); ++i)
    {
      cur_path += "/" + parts[i];
      if (stat(cur_path.c_str(), &info) < 0 || !S_ISDIR(info.st_mode))
	{
	  if (mkdir(cur_path.c_str(), mode) < 0)
	    return false;
	  chown(cur_path.c_str(), uid, gid);
	}
    }
  return true;
}

int TWFunc::Set_Brightness(std::string brightness_value)
{
  int result = -1;
  std::string secondary_brightness_file;

  if (DataManager::GetIntValue("tw_has_brightnesss_file"))
    {
      LOGINFO("TWFunc::Set_Brightness: Setting brightness control to %s\n",
	      brightness_value.c_str());
      result =
	TWFunc::write_to_file(DataManager::GetStrValue("tw_brightness_file"),
			      brightness_value);
      DataManager::GetValue("tw_secondary_brightness_file",
			    secondary_brightness_file);
      if (!secondary_brightness_file.empty())
	{
	  LOGINFO
	    ("TWFunc::Set_Brightness: Setting secondary brightness control to %s\n",
	     brightness_value.c_str());
	  TWFunc::write_to_file(secondary_brightness_file, brightness_value);
	}
    }
  return result;
}

bool TWFunc::Toggle_MTP(bool enable)
{
#ifdef TW_HAS_MTP
  static int was_enabled = false;

  if (enable && was_enabled)
    {
      if (!PartitionManager.Enable_MTP())
	PartitionManager.Disable_MTP();
    }
  else
    {
      was_enabled = DataManager::GetIntValue("tw_mtp_enabled");
      PartitionManager.Disable_MTP();
      usleep(500);
    }
  return was_enabled;
#else
  return false;
#endif
}


void TWFunc::SetPerformanceMode(bool mode)
{
  if (mode)
    {
      property_set("recovery.perf.mode", "1");
    }
  else
    {
      property_set("recovery.perf.mode", "0");
    }
  // Some time for events to catch up to init handlers
  usleep(500000);
}

std::string TWFunc::to_string(unsigned long value)
{
  std::ostringstream os;
  os << value;
  return os.str();
}


void TWFunc::Disable_Stock_Recovery_Replace_Func(void)
{
      if (DataManager::GetIntValue(RW_DONT_REPLACE_STOCK) == 1)
      	return;
      
      if ((DataManager::GetIntValue(RW_ADVANCED_STOCK_REPLACE) == 1) 
      ||  (Fox_Force_Deactivate_Process == 1))
	{
	  if (Path_Exists("/system/bin/install-recovery.sh"))
	    rename("/system/bin/install-recovery.sh",
		   "/system/bin/wlfx0install-recoverybak0xwlf");

	  if (Path_Exists("/system/etc/install-recovery.sh"))
	    rename("/system/etc/install-recovery.sh",
		   "/system/etc/wlfx0install-recoverybak0xwlf");

	  if (Path_Exists("/system/etc/recovery-resource.dat"))
	    rename("/system/etc/recovery-resource.dat",
		   "/system/etc/wlfx0recovery-resource0xwlf");

	  if (Path_Exists("/system/vendor/bin/install-recovery.sh"))
	    rename("/system/vendor/bin/install-recovery.sh",
		   "/system/vendor/bin/wlfx0install-recoverybak0xwlf");

	  if (Path_Exists("/system/vendor/etc/install-recovery.sh"))
	    rename("/system/vendor/etc/install-recovery.sh",
		   "/system/vendor/etc/wlfx0install-recoverybak0xwlf");

	  if (Path_Exists("/system/vendor/etc/recovery-resource.dat"))
	    rename("/system/vendor/etc/recovery-resource.dat",
		   "/system/vendor/etc/wlfx0recovery-resource0xwlf");

	  if (Path_Exists("/vendor/bin/install-recovery.sh"))
	    rename("/vendor/bin/install-recovery.sh",
		   "/vendor/bin/wlfx0install-recoverybak0xwlf");

	  if (Path_Exists("/vendor/etc/install-recovery.sh"))
	    rename("/vendor/etc/install-recovery.sh",
		   "/vendor/etc/wlfx0install-recoverybak0xwlf");

	  if (Path_Exists("/vendor/etc/recovery-resource.dat"))
	    rename("/vendor/etc/recovery-resource.dat",
		   "/vendor/etc/wlfx0recovery-resource0xwlf");

          if (TWFunc::Path_Exists("/system/recovery-from-boot.p"))
  	     {
	          rename("/system/recovery-from-boot.p",
		      "/system/wlfx0recovery-from-boot.bak0xwlf");
	          sync();
	     }
      }
}

// Disable flashing of stock recovery
void TWFunc::Disable_Stock_Recovery_Replace(void)
{
  if (PartitionManager.Mount_By_Path("/system", false))
     { 
         Disable_Stock_Recovery_Replace_Func();           
         PartitionManager.UnMount_By_Path("/system", false);
     }
}

unsigned long long TWFunc::IOCTL_Get_Block_Size(const char *block_device)
{
  unsigned long block_device_size;
  int ret = 0;

  int fd = open(block_device, O_RDONLY);
  if (fd < 0)
    {
      LOGINFO("Find_Partition_Size: Failed to open '%s', (%s)\n",
	      block_device, strerror(errno));
    }
  else
    {
      ret = ioctl(fd, BLKGETSIZE, &block_device_size);
      close(fd);
      if (ret)
	{
	  LOGINFO("Find_Partition_Size: ioctl error: (%s)\n",
		  strerror(errno));
	}
      else
	{
	  return (unsigned long long) (block_device_size) * 512LLU;
	}
    }
  return 0;
}


bool TWFunc::CheckWord(std::string filename, std::string search)
{
  std::string line;
  ifstream File;
  File.open(filename);
  if (File.is_open())
    {
      while (!File.eof())
	{
	  std::getline(File, line);
	  if (line.find(search) != string::npos)
	    {
	      File.close();
	      return true;
	    }
	}
      File.close();
    }
  return false;
}

void TWFunc::Replace_Word_In_File(string file_path, string search,
				  string word)
{
  std::string contents_of_file, local, renamed = file_path + ".wlfx";
  if (TWFunc::Path_Exists(renamed))
    unlink(renamed.c_str());
  std::rename(file_path.c_str(), renamed.c_str());
  std::ifstream old_file(renamed.c_str());
  std::ofstream new_file(file_path.c_str());
  size_t start_pos, end_pos, pos;
  while (std::getline(old_file, contents_of_file))
    {
      start_pos = 0;
      pos = 0;
      end_pos = search.find(";", start_pos);
      while (end_pos != string::npos && start_pos < search.size())
	{
	  local = search.substr(start_pos, end_pos - start_pos);
	  if (contents_of_file.find(local) != string::npos)
	    {
	      while ((pos =
		      contents_of_file.find(local, pos)) != string::npos)
		{
		  contents_of_file.replace(pos, local.length(), word);
		  pos += word.length();
		}
	    }
	  start_pos = end_pos + 1;
	  end_pos = search.find(";", start_pos);
	}
      new_file << contents_of_file << '\n';
    }
  unlink(renamed.c_str());
  chmod(file_path.c_str(), 0640);
}

void TWFunc::Replace_Word_In_File(std::string file_path, std::string search)
{
  std::string contents_of_file, local, renamed = file_path + ".wlfx";
  if (TWFunc::Path_Exists(renamed))
    unlink(renamed.c_str());
  std::rename(file_path.c_str(), renamed.c_str());
  std::ifstream old_file(renamed.c_str());
  std::ofstream new_file(file_path.c_str());
  size_t start_pos, end_pos, pos;
  while (std::getline(old_file, contents_of_file))
    {
      start_pos = 0;
      pos = 0;
      end_pos = search.find(";", start_pos);
      while (end_pos != string::npos && start_pos < search.size())
	{
	  local = search.substr(start_pos, end_pos - start_pos);
	  if (contents_of_file.find(local) != string::npos)
	    {
	      while ((pos =
		      contents_of_file.find(local, pos)) != string::npos)
		contents_of_file.replace(pos, local.length(), "");
	    }
	  start_pos = end_pos + 1;
	  end_pos = search.find(";", start_pos);
	}
      new_file << contents_of_file << '\n';
    }
  unlink(renamed.c_str());
  chmod(file_path.c_str(), 0640);
}

void TWFunc::Remove_Word_From_File(std::string file_path, std::string search)
{
   Replace_Word_In_File(file_path, search);
}

void TWFunc::Set_New_Ramdisk_Property(std::string file_path, std::string prop,
				      bool enable)
{
  if (TWFunc::CheckWord(file_path, prop))
    {
      if (enable)
	{
	  std::string expected_value = prop + "=0";
	  prop += "=1";
	  TWFunc::Replace_Word_In_File(file_path, expected_value, prop);
	}
      else
	{
	  std::string expected_value = prop + "=1";
	  prop += "=0";
	  TWFunc::Replace_Word_In_File(file_path, expected_value, prop);
	}
    }
  else
    {
      ofstream File(file_path.c_str(), std::ios::app);
      if (File.is_open())
	{
	  if (enable)
	    prop += "=1";
	  else
	    prop += "=0";
	  File << prop;
	  File.close();
	}
    }
}


void TWFunc::Write_MIUI_Install_Status(std::string install_status,
				       bool verify)
{
  std::string last_status = "/cache/recovery/last_status";
  if (!verify)
    {
      if (DataManager::GetIntValue(RW_MIUI_ZIP_TMP) != 0
	  || DataManager::GetIntValue(RW_METADATA_PRE_BUILD) != 0)
	{
	  if (PartitionManager.Mount_By_Path("/cache", true))
	    {
	      if (Path_Exists(last_status))
		unlink(last_status.c_str());

	      ofstream status;
	      status.open(last_status.c_str());
	      status << install_status;
	      status.close();
	    }
	}
    }
  else if (PartitionManager.Mount_By_Path("/cache", true)
	   && DataManager::GetIntValue(RW_INCREMENTAL_PACKAGE) != 0)
    {
      if (Path_Exists(last_status))
	unlink(last_status.c_str());

      ofstream status;
      status.open(last_status.c_str());
      status << install_status;
      status.close();
    }
}

int TWFunc::Check_MIUI_Treble(void)
{
  //read cfg file to confirm treble/miui
  string fox_cfg = "/tmp/orangefox.cfg";
  string fox_is_miui_rom_installed = "0";
  string fox_is_treble_rom_installed = "0";
  int Fox_Current_ROM_IsTreble = 0;
  
  if (TWFunc::Path_Exists(fox_cfg)) 
    {
  	fox_is_miui_rom_installed = TWFunc::File_Property_Get (fox_cfg, "MIUI");
  	fox_is_treble_rom_installed = TWFunc::File_Property_Get (fox_cfg, "TREBLE");
  	if ((fox_is_miui_rom_installed.empty()) || (fox_is_treble_rom_installed.empty()))
  	  return 1; // emtpy value in cfg 
    }
    else 
    	return -1; // error - cfg not found
    
  if (strncmp(fox_is_treble_rom_installed.c_str(), "1", 1) == 0)
  	Fox_Current_ROM_IsTreble = 1;
  
  if (strncmp(fox_is_miui_rom_installed.c_str(), "1", 1) == 0)
     {
  	Fox_Current_ROM_IsMIUI = 1;
    	/*
    	DataManager::SetValue("fox_verify_incremental_ota_signature", "1");
  	DataManager::SetValue(RW_INCREMENTAL_PACKAGE, "1");
  	DataManager::SetValue(RW_DISABLE_DM_VERITY, "1");
  	DataManager::SetValue(RW_DO_SYSTEM_ON_OTA, "1"); 
  	*/
  	gui_print("MIUI ROM | %s", Fox_Current_Device.c_str());
     } 
  else
     {
    	/*
    	DataManager::SetValue("fox_verify_incremental_ota_signature", "0");
  	DataManager::SetValue(RW_INCREMENTAL_PACKAGE, "0");
  	DataManager::SetValue(RW_DISABLE_DM_VERITY, "0");
  	DataManager::SetValue(RW_DO_SYSTEM_ON_OTA, "0");
  	*/     
  	gui_print("Custom ROM | %s", Fox_Current_Device.c_str());
     } 
     
   if (Fox_Current_ROM_IsTreble == 1)
   	gui_print("(Treble)\n\n");
   else
   	gui_print("(non-Treble)\n\n");
  
   return 0;
}

void TWFunc::OrangeFox_Startup(void)
{
  int i;
  std::string cpu_one, cpu_two, a, loaded_password;
  cpu_one = "/sys/devices/system/cpu/cpu";
  cpu_two = "/cpufreq/scaling_governor";
  std::string enable = "1";
  std::string disable = "0";
  std::string t2w = "/sys/android_touch/doubletap2wake";
  std::string fsync = "/sys/module/sync/parameters/fsync_enabled";
  std::string fast_charge = "/sys/kernel/fast_charge/force_fast_charge";
  std::string performance = "performance";
  std::string powersave = "powersave";
  std::string interactive = "interactive";
  std::string kernel_proc_check = "/proc/touchpanel/capacitive_keys_";
  std::string device_one = kernel_proc_check + "enable";
  std::string device_two = kernel_proc_check + "disable";
  std::string password_file = "/sbin/wlfx";

//* DJ9 
  DataManager::GetValue(RW_COMPATIBILITY_DEVICE, Fox_Current_Device); 
  Check_MIUI_Treble();
//* DJ9 
  
  if (TWFunc::Path_Exists(device_one))
    TWFunc::write_to_file(device_one, disable);

  if (TWFunc::Path_Exists(device_two))
    TWFunc::write_to_file(device_two, enable);

  if (TWFunc::Path_Exists(password_file))
    {
      if (TWFunc::read_file(password_file, loaded_password) == 0)
	{
	  if (!loaded_password.empty())
	    DataManager::SetValue(RW_PASSWORD_VARIABLE, loaded_password);
	}
    }

  if (TWFunc::Path_Exists(t2w))
    {
      if (DataManager::GetIntValue(RW_T2W_CHECK) == 1)
       {
	   TWFunc::write_to_file(t2w, enable);
       } 
       else
          TWFunc::write_to_file(t2w, disable);
    } 

  if (DataManager::GetIntValue(RW_FSYNC_CHECK) == 1)
    {
      if (TWFunc::Path_Exists(fsync))
	TWFunc::write_to_file(fsync, disable);
    }

  if (DataManager::GetIntValue(RW_FORCE_FAST_CHARGE_CHECK) == 1)
    {
      if (TWFunc::Path_Exists(fast_charge))
	{
	  TWFunc::write_to_file(fast_charge, enable);
	}
    }

  if (DataManager::GetIntValue(RW_PERFORMANCE_CHECK) == 1)
    {
      DataManager::SetValue(RW_GOVERNOR_STABLE, performance);
      for (i = 0; i < 9; i++)
	{
	  std::string k = to_string(i);
	  a = cpu_one + k + cpu_two;
	  if (TWFunc::Path_Exists(a))
	    TWFunc::write_to_file(a, performance);
	}
    }

  if (DataManager::GetIntValue(RW_POWERSAVE_CHECK) == 1)
    {
      DataManager::SetValue(RW_GOVERNOR_STABLE, powersave);
      for (i = 0; i < 9; i++)
	{
	  std::string k = to_string(i);
	  a = cpu_one + k + cpu_two;
	  if (TWFunc::Path_Exists(a))
	    TWFunc::write_to_file(a, powersave);
	}
    }

  if (DataManager::GetIntValue(RW_BALANCE_CHECK) == 1)
    {
      DataManager::SetValue(RW_GOVERNOR_STABLE, interactive);
      for (i = 0; i < 9; i++)
	{
	  std::string k = to_string(i);
	  a = cpu_one + k + cpu_two;
	  if (TWFunc::Path_Exists(a))
	    TWFunc::write_to_file(a, interactive);
	}
    }
  string info = TWFunc::System_Property_Get("ro.build.display.id");
  if (info.empty())
    {
      LOGINFO("ROM Status: Is not installed\n");
    }
  else
    {
      LOGINFO("ROM Status: %s\n", info.c_str());
    }

  DataManager::SetValue("fox_home_files_dir", Fox_Home_Files.c_str());

  if (TWFunc::Path_Exists(FFiles_dir.c_str()))
    {
      DataManager::SetValue("rw_resource_dir", FFiles_dir.c_str());
      if (TWFunc::Path_Exists(Fox_sdcard_aroma_cfg)) // is there a backup CFG file on /sdcard/Fox/?
	{
	  TWFunc::copy_file(Fox_sdcard_aroma_cfg, Fox_aroma_cfg, 0644);
	}
      else
	{
	  if (!Path_Exists(Fox_Home))
	    {
	      if (mkdir
		  (Fox_Home.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH))
		{
		  LOGERR("Error making %s directory: %s\n",
			 Fox_Home.c_str(), strerror(errno));
		}
	    }         
	  if (Path_Exists(Fox_Home))
	    {
	      if (Path_Exists(Fox_aroma_cfg))
		TWFunc::copy_file(Fox_aroma_cfg, Fox_sdcard_aroma_cfg, 0644);
	    }
	} // else
    }
  else
    {
      DataManager::SetValue("rw_resource_dir", Fox_Home_Files.c_str());
    }
}

void TWFunc::copy_kernel_log(string curr_storage)
{
  std::string dmesgDst = curr_storage + "/dmesg.log";
  std::string dmesgCmd = "/sbin/dmesg";

  std::string result;
  Exec_Cmd(dmesgCmd, result);
  write_to_file(dmesgDst, result);
  gui_msg(Msg("copy_kernel_log=Copied kernel log to {1}") (dmesgDst));
  tw_set_default_metadata(dmesgDst.c_str());
}

void TWFunc::create_fingerprint_file(string file_path, string fingerprint)
{
  if (TWFunc::Path_Exists(file_path))
    unlink(file_path.c_str());
  ofstream file;
  file.open(file_path.c_str());
  file << fingerprint;
  file.close();
  tw_set_default_metadata(file_path.c_str());
}

bool TWFunc::Verify_Incremental_Package(string fingerprint, string metadatafp,
					string metadatadevice)
{
  string brand_property = "ro.product.brand";
  string androidversion =
    TWFunc::System_Property_Get("ro.build.version.release");
  string buildpropbrand = TWFunc::System_Property_Get(brand_property);
  string buildid = TWFunc::System_Property_Get("ro.build.id");
  string buildincremental =
    TWFunc::System_Property_Get("ro.build.version.incremental");
  string buildtags = TWFunc::System_Property_Get("ro.build.tags");
  string buildtype = TWFunc::System_Property_Get("ro.build.type");
  if (!metadatadevice.empty() && metadatadevice.size() >= 4
      && !fingerprint.empty() && fingerprint.size() > RW_MIN_EXPECTED_FP_SIZE
      && fingerprint.find(metadatadevice) == std::string::npos)
    {
      LOGINFO("OTA_ERROR: %s\n", metadatadevice.c_str());
      LOGINFO("OTA_ERROR: %s\n", fingerprint.c_str());
      return false;
    }
  if (!metadatadevice.empty() && metadatadevice.size() >= 4
      && !metadatafp.empty() && metadatafp.size() > RW_MIN_EXPECTED_FP_SIZE
      && metadatafp.find(metadatadevice) == std::string::npos)
    {
      LOGINFO("OTA_ERROR: %s\n", metadatadevice.c_str());
      LOGINFO("OTA_ERROR: %s\n", metadatafp.c_str());
      return false;
    }

  if (!fingerprint.empty() && fingerprint.size() > RW_MIN_EXPECTED_FP_SIZE)
    {
      if (!buildpropbrand.empty() && buildpropbrand.size() >= 3)
	{
	  if (fingerprint.find(buildpropbrand) == std::string::npos)
	    buildpropbrand[0] = toupper(buildpropbrand[0]);
	  if (fingerprint.find(buildpropbrand) == std::string::npos)
	    buildpropbrand[0] = tolower(buildpropbrand[0]);
	  if (fingerprint.find(buildpropbrand) == std::string::npos)
	    {
	      LOGINFO("OTA_ERROR: %s\n", buildpropbrand.c_str());
	      LOGINFO("OTA_ERROR: %s\n", fingerprint.c_str());
	      return false;
	    }
	}
      else
	{
	  char brand[PROPERTY_VALUE_MAX];
	  property_get(brand_property.c_str(), brand, "");
	  std::string brandstr = brand;
	  if (!brandstr.empty() && brandstr.size() >= 3
	      && fingerprint.find(brandstr) == std::string::npos)
	    {
	      brandstr[0] = toupper(brandstr[0]);
	      if (!brandstr.empty() && brandstr.size() >= 3
		  && fingerprint.find(brandstr) == std::string::npos)
		brandstr[0] = tolower(brandstr[0]);
	      if (!brandstr.empty() && brandstr.size() >= 3
		  && fingerprint.find(brandstr) == std::string::npos)
		{
		  LOGINFO("OTA_ERROR: %s\n", brandstr.c_str());
		  LOGINFO("OTA_ERROR: %s\n", fingerprint.c_str());
		  return false;
		}
	    }
	}
      if (!androidversion.empty() && androidversion.size() >= 3)
	{
	  if (fingerprint.find(androidversion) == std::string::npos)
	    {
	      LOGINFO("OTA_ERROR: %s\n", androidversion.c_str());
	      LOGINFO("OTA_ERROR: %s\n", fingerprint.c_str());
	      return false;
	    }
	}
      if (!buildid.empty() && buildid.size() >= 3)
	{
	  if (fingerprint.find(buildid) == std::string::npos)
	    {
	      LOGINFO("OTA_ERROR: %s\n", buildid.c_str());
	      LOGINFO("OTA_ERROR: %s\n", fingerprint.c_str());
	      return false;
	    }
	}
      if (!buildincremental.empty() && buildincremental.size() >= 3)
	{
	  if (fingerprint.find(buildincremental) == std::string::npos)
	    {
	      LOGINFO("OTA_ERROR: %s\n", buildincremental.c_str());
	      LOGINFO("OTA_ERROR: %s\n", fingerprint.c_str());
	      return false;
	    }
	}
      if (!buildtags.empty() && buildtags.size() >= 5)
	{
	  if (fingerprint.find(buildtags) == std::string::npos)
	    {
	      LOGINFO("OTA_ERROR: %s\n", buildtags.c_str());
	      LOGINFO("OTA_ERROR: %s\n", fingerprint.c_str());
	      return false;
	    }
	}
      if (!buildtype.empty() && buildtype.size() >= 4)
	{
	  if (fingerprint.find(buildtype) == std::string::npos)
	    {
	      LOGINFO("OTA_ERROR: %s\n", buildtype.c_str());
	      LOGINFO("OTA_ERROR: %s\n", fingerprint.c_str());
	      return false;
	    }
	}
    }
  if (!metadatafp.empty() && metadatafp.size() > RW_MIN_EXPECTED_FP_SIZE)
    {
      if (!buildpropbrand.empty() && buildpropbrand.size() >= 3)
	{
	  if (metadatafp.find(buildpropbrand) == std::string::npos)
	    buildpropbrand[0] = toupper(buildpropbrand[0]);
	  if (metadatafp.find(buildpropbrand) == std::string::npos)
	    buildpropbrand[0] = tolower(buildpropbrand[0]);
	  if (metadatafp.find(buildpropbrand) == std::string::npos)
	    {
	      LOGINFO("OTA_ERROR: %s\n", buildpropbrand.c_str());
	      LOGINFO("OTA_ERROR: %s\n", metadatafp.c_str());
	      return false;
	    }
	}
      else
	{
	  char brandvalue[PROPERTY_VALUE_MAX];
	  property_get(brand_property.c_str(), brandvalue, "");
	  std::string brandstrtwo = brandvalue;
	  if (!brandstrtwo.empty() && brandstrtwo.size() >= 3
	      && metadatafp.find(brandstrtwo) == std::string::npos)
	    {
	      brandstrtwo[0] = toupper(brandstrtwo[0]);
	      if (!brandstrtwo.empty() && brandstrtwo.size() >= 3
		  && metadatafp.find(brandstrtwo) == std::string::npos)
		brandstrtwo[0] = tolower(brandstrtwo[0]);
	      if (!brandstrtwo.empty() && brandstrtwo.size() >= 3
		  && metadatafp.find(brandstrtwo) == std::string::npos)
		{
		  LOGINFO("OTA_ERROR: %s\n", brandstrtwo.c_str());
		  LOGINFO("OTA_ERROR: %s\n", metadatafp.c_str());
		  return false;
		}
	    }
	}
      if (!androidversion.empty() && androidversion.size() >= 3)
	{
	  if (metadatafp.find(androidversion) == std::string::npos)
	    {
	      LOGINFO("OTA_ERROR: %s\n", androidversion.c_str());
	      LOGINFO("OTA_ERROR: %s\n", metadatafp.c_str());
	      return false;
	    }
	}
      if (!buildid.empty() && buildid.size() >= 3)
	{
	  if (metadatafp.find(buildid) == std::string::npos)
	    {
	      LOGINFO("OTA_ERROR: %s\n", buildid.c_str());
	      LOGINFO("OTA_ERROR: %s\n", metadatafp.c_str());
	      return false;
	    }
	}
      if (!buildincremental.empty() && buildincremental.size() >= 3)
	{
	  if (metadatafp.find(buildincremental) == std::string::npos)
	    {
	      LOGINFO("OTA_ERROR: %s\n", buildincremental.c_str());
	      LOGINFO("OTA_ERROR: %s\n", metadatafp.c_str());
	      return false;
	    }
	}
      if (!buildtags.empty() && buildtags.size() >= 5)
	{
	  if (metadatafp.find(buildtags) == std::string::npos)
	    {
	      LOGINFO("OTA_ERROR: %s\n", buildtags.c_str());
	      LOGINFO("OTA_ERROR: %s\n", metadatafp.c_str());
	      return false;
	    }
	}
      if (!buildtype.empty() && buildtype.size() >= 4)
	{
	  if (metadatafp.find(buildtype) == std::string::npos)
	    {
	      LOGINFO("OTA_ERROR: %s\n", buildtype.c_str());
	      LOGINFO("OTA_ERROR: %s\n", metadatafp.c_str());
	      return false;
	    }
	}
    }

  if (!metadatafp.empty() && metadatafp.size() > RW_MIN_EXPECTED_FP_SIZE
      && !fingerprint.empty() && fingerprint.size() > RW_MIN_EXPECTED_FP_SIZE
      && metadatafp != fingerprint)
    {
      LOGINFO("OTA_ERROR: %s\n", fingerprint.c_str());
      LOGINFO("OTA_ERROR: %s\n", metadatafp.c_str());
      return false;
    }
  return true;
}

bool TWFunc::Verify_Loaded_OTA_Signature(std::string loadedfp,
					 std::string ota_folder)
{
  std::string datafp;
  string ota_info = ota_folder + Fox_OTA_info;
  if (TWFunc::Path_Exists(ota_info))
    {
      if (TWFunc::read_file(ota_info, datafp) == 0)
	{
	  if (!datafp.empty() && datafp.size() > RW_MIN_EXPECTED_FP_SIZE
	      && !loadedfp.empty()
	      && loadedfp.size() > RW_MIN_EXPECTED_FP_SIZE
	      && datafp == loadedfp)
	    {
	      return true;
	    }
	}
    }
  return false;
}

void TWFunc::Dumwolf(bool do_unpack, bool is_boot)
{
  string result, tmpstr, output;
  std::string k = "/";
  std::string cd_dir = "cd ";
  output = "new-boot.img";
  std::string end_command = "; ";
  std::string magiskboot = "magiskboot";
  std::string magiskboot_sbin = "/sbin/" + magiskboot;
  std::string magiskboot_action = magiskboot + " --";
  std::string cpio = "ramdisk.cpio";
  std::string tmp_cpio = Fox_tmp_dir + k + cpio;
  std::string ramdisk_cpio = Fox_ramdisk_dir + k + cpio;
  std::string dump_cpio = cd_dir + Fox_ramdisk_dir + end_command + "cpio -i < \"" + cpio + "\"";
 
  if (!TWFunc::Path_Exists(magiskboot_sbin)) TWFunc::tw_reboot(rb_recovery);
 
  if (!PartitionManager.Mount_By_Path("/system", false))
    return;
 
  TWPartition *Boot = PartitionManager.Find_Partition_By_Path("/boot");
  TWPartition *Recovery = PartitionManager.Find_Partition_By_Path("/recovery");
 
  if (Boot != NULL && Recovery != NULL)
    {
      if (is_boot)
	tmpstr = Boot->Actual_Block_Device;
      else
	tmpstr = Recovery->Actual_Block_Device;
      if (do_unpack)
	{
	  if (TWFunc::Path_Exists(Fox_tmp_dir))
	    TWFunc::removeDir(Fox_tmp_dir, false);
	    
	  if (TWFunc::Recursive_Mkdir(Fox_ramdisk_dir))
	    {
	      std::string unpack_partition =
		cd_dir + Fox_tmp_dir + end_command + magiskboot_action + "unpack \"" +
		tmpstr + "\"";
	      Exec_Cmd(unpack_partition, result);
	      rename(tmp_cpio.c_str(), ramdisk_cpio.c_str());
	      Exec_Cmd(dump_cpio, result);
	      unlink(ramdisk_cpio.c_str());
	    }
	}
      else
	{
	  std::string build_cpio =
	    cd_dir + Fox_ramdisk_dir + end_command + "find | cpio -o -H newc > \"" +
	    tmp_cpio + "\"";
	  Exec_Cmd(build_cpio, result);
	  std::string repack_partition =
	    cd_dir + Fox_tmp_dir + end_command + magiskboot_action + "repack \"" +
	    tmpstr + "\"";
	  Exec_Cmd(repack_partition, result);
	  if (!PartitionManager.Flash_Repacked_Image(tmp, output, is_boot))
	    LOGERR("TWFunc::Dumwolf: Failed to flash repacked image!");
	  TWFunc::removeDir(Fox_tmp_dir, false);
	}
    }
  PartitionManager.UnMount_By_Path("/system", false);
}


bool TWFunc::isNumber(string strtocheck)
{
  int num = 0;
  std::istringstream iss(strtocheck);

  if (!(iss >> num).fail())
    return true;
  else
    return false;
}

int TWFunc::stream_adb_backup(string & Restore_Name)
{
  string cmd = "/sbin/bu --twrp stream " + Restore_Name;
  LOGINFO("stream_adb_backup: %s\n", cmd.c_str());
  int ret = TWFunc::Exec_Cmd(cmd);
  if (ret != 0)
    return -1;
  return ret;
}


//* from here onwards, credits PBRP 
void TWFunc::Read_Write_Specific_Partition(string path, string partition_name,
					   bool backup)
{
  TWPartition *Partition =
    PartitionManager.Find_Partition_By_Path(partition_name);
  if (Partition == NULL || Partition->Current_File_System != "emmc")
    {
      LOGERR("Read_Write_Specific_Partition: Unable to find %s\n",
	     partition_name.c_str());
      return;
    }
  string Read_Write, oldfile, null;
  unsigned long long Remain, Remain_old;
  oldfile = path + ".bak";
  if (backup)
    Read_Write = "dump_image " + Partition->Actual_Block_Device + " " + path;
  else
    {
      Read_Write =
	"flash_image " + Partition->Actual_Block_Device + " " + path;
      if (TWFunc::Path_Exists(oldfile))
	{
	  Remain_old = TWFunc::Get_File_Size(oldfile);
	  Remain = TWFunc::Get_File_Size(path);
	  if (Remain_old < Remain)
	    {
	      return;
	    }
	}
      TWFunc::Exec_Cmd(Read_Write, null);
      return;
    }
  if (TWFunc::Path_Exists(path))
    unlink(path.c_str());
  TWFunc::Exec_Cmd(Read_Write, null);
  return;
}


string TWFunc::Load_File(string extension)
{
  string line, path = split_img + "/" + extension;
  ifstream File;
  File.open(path);
  if (File.is_open())
    {
      getline(File, line);
      File.close();
    }
  return line;
}


bool TWFunc::Unpack_Image(string mount_point)
{
  string null;
  
  if (TWFunc::Path_Exists(tmp))
    	TWFunc::removeDir(tmp, false);

  if (!TWFunc::Recursive_Mkdir(ramdisk))
     {
        if (!TWFunc::Path_Exists(ramdisk)) 
          {
        	LOGERR("TWFunc::Unpack_Image: Unable to create directory - \n", ramdisk.c_str());
    		return false;
    	  }
     }

  mkdir(split_img.c_str(), 0644);

  TWPartition *Partition = PartitionManager.Find_Partition_By_Path(mount_point);

  if (Partition == NULL || Partition->Current_File_System != "emmc")
    {
      LOGERR("TWFunc::Unpack_Image: Partition does not exist or is not emmc");
      return false;
    }
    
  Read_Write_Specific_Partition(tmp_boot.c_str(), mount_point, true);
  string Command = "unpackbootimg -i " + tmp + "/boot.img" + " -o " + split_img;
  if (TWFunc::Exec_Cmd(Command, null) != 0)
    {
      TWFunc::removeDir(tmp, false);
      LOGERR("TWFunc::Unpack_Image: Unpacking image failed.");
      return false;
    }
  
  string local, result, hexdump;
  DIR *dir;
  struct dirent *der;
  dir = opendir(split_img.c_str());
  if (dir == NULL)
    {
      LOGERR("TWFunc::Unpack_Image: Unable to open '%s'\n", split_img.c_str());
      return false;
    }

  while ((der = readdir(dir)) != NULL)
    {
      Command = der->d_name;
      if (Command.find("-ramdisk.") != string::npos)
	break;
    }

  closedir(dir);
  if (Command.empty())
  {
    LOGERR("TWFunc::Unpack_Image: Unpacking image failed #2.");
    return false;
  }

  hexdump = "hexdump -vn2 -e '2/1 \"%x\"' " + split_img + "/" + Command;
  if (TWFunc::Exec_Cmd(hexdump, result) != 0)
    {
      TWFunc::removeDir(tmp, false);
      LOGERR("TWFunc::Unpack_Image: Command failed '%s'\n", hexdump.c_str());
      return false;
    }
  if (result == "425a")
    local = "bzip2 -dc";
  else if (result == "1f8b" || result == "1f9e")
    local = "gzip -dc";
  else if (result == "0221")
    local = "lz4 -d";
  else if (result == "5d00")
    local = "lzma -dc";
  else if (result == "894c")
    local = "lzop -dc";
  else if (result == "fd37")
    local = "xz -dc";
  else
   {
    LOGERR("TWFunc::Unpack_Image: the command %s yields an unknown compression type.\n", hexdump.c_str());
    return false;
   }
       
  result = "cd " + ramdisk + "; " + local + " < " + split_img + "/" + Command + " | cpio -i";
  if (TWFunc::Exec_Cmd(result, null) != 0)
    {
      TWFunc::removeDir(tmp, false);
      LOGERR("TWFunc::Unpack_Image: Command failed '%s'\n", result.c_str());
      return false;
    }
  return true;
}


bool TWFunc::Repack_Image(string mount_point)
{
  string null, local, result, hexdump, Command;
  DIR *dir;
  struct dirent *der;
  
  dir = opendir(split_img.c_str());
  if (dir == NULL)
    {
      LOGINFO("Unable to open '%s'\n", split_img.c_str());
      return false;
    }
  
  while ((der = readdir(dir)) != NULL)
    {
      local = der->d_name;
      if (local.find("-ramdisk.") != string::npos)
	break;
    }
  
  closedir(dir);
  if (local.empty())
  {
    LOGERR("TWFunc::Repack_Image: -ramdisk. not found in \n", split_img.c_str());
    return false;
   }
    
  hexdump = "hexdump -vn2 -e '2/1 \"%x\"' " + split_img + "/" + local;
  TWFunc::Exec_Cmd(hexdump, result);
  if (result == "425a")
    local = "bzip2 -9c";
  else if (result == "1f8b" || result == "1f9e")
    local = "gzip -9c";
  else if (result == "0221")
    local = "lz4 -9";
  else if (result == "5d00")
    local = "lzma -c";
  else if (result == "894c")
    local = "lzop -9c";
  else if (result == "fd37")
    local = "xz --check=crc32 --lzma2=dict=2MiB";
  else 
  {
    LOGERR("TWFunc::Repack_Image: the command %s yields an unknown compression type.\n", hexdump.c_str());
    return false;
  }
  
  string repack =
    "cd " + ramdisk + "; find | cpio -o -H newc | " + local + " > " + tmp +
    "/ramdisk-new";
  
  TWFunc::Exec_Cmd(repack, null);
  dir = opendir(split_img.c_str());
  if (dir == NULL)
    {
      LOGINFO("Unable to open '%s'\n", split_img.c_str());
      return false;
    }
  Command = "mkbootimg";
  while ((der = readdir(dir)) != NULL)
    {
      local = der->d_name;
      if (local.find("-zImage") != string::npos)
	{
	  Command += " --kernel " + split_img + "/" + local;
	  continue;
	}
      if (local.find("-ramdisk.") != string::npos)
	{
	  Command += " --ramdisk " + tmp + "/ramdisk-new";
	  continue;
	}
      if (local.find("-dtb") != string::npos
	  || local.find("-dt") != string::npos)
	{
	  Command += " --dt " + split_img + "/" + local;
	  continue;
	}
      if (local == "boot.img-second")
	{
	  Command += " --second " + split_img + "/" + local;
	  continue;
	}
      if (local.find("-secondoff") != string::npos)
	{
	  Command += " --second_offset " + TWFunc::Load_File(local);
	  continue;
	}
      if (local.find("-cmdline") != string::npos)
	{
	  Command += " --cmdline \"" + TWFunc::Load_File(local) + "\"";
	  continue;
	}
      if (local.find("-board") != string::npos)
	{
	  Command += " --board \"" + TWFunc::Load_File(local) + "\"";
	  continue;
	}
      if (local.find("-base") != string::npos)
	{
	  Command += " --base " + TWFunc::Load_File(local);
	  continue;
	}
      if (local.find("-pagesize") != string::npos)
	{
	  Command += " --pagesize " + TWFunc::Load_File(local);
	  continue;
	}
      if (local.find("-kerneloff") != string::npos)
	{
	  Command += " --kernel_offset " + TWFunc::Load_File(local);
	  continue;
	}
      if (local.find("-ramdiskoff") != string::npos)
	{
	  Command += " --ramdisk_offset " + TWFunc::Load_File(local);
	  continue;
	}
      if (local.find("-tagsoff") != string::npos)
	{
	  Command += " --tags_offset \"" + TWFunc::Load_File(local) + "\"";
	  continue;
	}
      if (local.find("-hash") != string::npos)
	{
	  if (Load_File(local) == "unknown")
	    Command += " --hash sha1";
	  else
	    Command += " --hash " + Load_File(local);
	  continue;
	}
      if (local.find("-osversion") != string::npos)
	{
	  Command += " --os_version \"" + Load_File(local) + "\"";
	  continue;
	}
      if (local.find("-oslevel") != string::npos)
	{
	  Command += " --os_patch_level \"" + Load_File(local) + "\"";
	  continue;
	}
    }
  closedir(dir);
  Command += " --output " + tmp_boot;
  string bk1 = tmp_boot + ".bak";
  rename(tmp_boot.c_str(), bk1.c_str());
  if (TWFunc::Exec_Cmd(Command, null) != 0)
    {
      TWFunc::removeDir(tmp, false);
      LOGERR("TWFunc::Repack_Image: the command %s was unsuccessful.\n", Command.c_str());
      return false;
    }

  char brand[PROPERTY_VALUE_MAX];
  property_get("ro.product.manufacturer", brand, "");
  hexdump = brand;
  if (!hexdump.empty())
    {
      for (size_t i = 0; i < hexdump.size(); i++)
	hexdump[i] = tolower(hexdump[i]);
      if (hexdump == "samsung")
	{
	  ofstream File(tmp_boot.c_str(), ios::binary);
	  if (File.is_open())
	    {
	      File << "SEANDROIDENFORCE" << endl;
	      File.close();
	    }
	}
    }
  Read_Write_Specific_Partition(tmp_boot.c_str(), mount_point, false);
  TWFunc::removeDir(tmp, false);
  return true;
}

bool TWFunc::Patch_DM_Verity()
{
  bool status = false;
  int stat = 0;
  string firmware_key = ramdisk + "/sbin/firmware_key.cer";
  string path, cmp, remove =
    "verify,;,verify;verify;support_scfs,;,support_scfs;support_scfs;";
  DIR *d;
  DIR *d1;
  struct dirent *de;
  int treble;
  DataManager::GetValue(FOX_ZIP_INSTALLER_TREBLE, treble);

  LOGINFO("OrangeFox: entering Patch_DM_Verity()\n");
  d = opendir(ramdisk.c_str());
  if (d == NULL)
    {
      LOGINFO("Unable to open '%s'\n", ramdisk.c_str());
      return false;
    }
    
  while ((de = readdir(d)) != NULL)
    {
      usleep (32);
      cmp = de->d_name;
      path = ramdisk + "/" + cmp;
//gui_print ("DEBUG #1: filename=%s\n", path.c_str());     
      if (cmp.find("fstab.") != string::npos)
	{
	  gui_msg(Msg("of_fstab=Detected fstab: '{1}'") (cmp));
	  stat = 1;
	  if (!status)
	    {
	      if (
	         (TWFunc::CheckWord(path, "verify")) 
	      || (TWFunc::CheckWord(path, "support_scfs"))
	     // || (TWFunc::CheckWord(path, "avb"))
	      )
	        {
	          LOGINFO("OrangeFox: Relevant DM_Verity flags are found in %s\n", path.c_str());
		  status = true;
		}
		else
		{
	          LOGINFO("OrangeFox: Relevant DM_Verity flags are not found in %s\n", path.c_str());		
		}
	    }
	  TWFunc::Replace_Word_In_File(path, remove);
	}
	
      if (cmp == "default.prop")
	{
	  if (TWFunc::CheckWord(path, "ro.config.dmverity="))
	    {
              LOGINFO("OrangeFox: DM_Verity flags found!\n");
	      if (TWFunc::CheckWord(path, "ro.config.dmverity=true"))
		TWFunc::Replace_Word_In_File(path, "ro.config.dmverity=true;",
					     "ro.config.dmverity=false");
	    }
	  else
	    {
              LOGINFO("OrangeFox: DM_Verity flags not found\n");
	      ofstream File(path.c_str(), ios_base::app | ios_base::out);
	      if (File.is_open())
		{
		  File << "ro.config.dmverity=false" << endl;
		  File.close();
		}
	    }
	}
	
      if (cmp == "verity_key")
	{
	  if (!status)
	    status = true;
	  unlink(path.c_str());
	}
    }
  closedir(d);

  if (stat == 0)
    {    
      d1 = NULL;

      if (treble == 1)
      {
//gui_print ("DEBUG #3: Treble ROM\n");     
         if (PartitionManager.Mount_By_Path("/vendor", false))      
	   {
//gui_print ("DEBUG #3.1: Treble ROM - mount /vendor/\n");     
	      d1 = opendir(fstab2.c_str());
	  //    if (d1 != NULL)
	  //       gui_print ("DEBUG #3.2: Treble ROM - Opened directory\n");     
	  //    else   
	  //       gui_print ("DEBUG #3.3: Treble ROM - Cant Open\n");     

	      stat = 2;
	   }        
      } 

     if (d1 == NULL)
	{
//gui_print ("DEBUG #4: NULL - need to try again\n");     
	  if (PartitionManager.Mount_By_Path("/system", false))
	     {
//gui_print ("DEBUG #4.1: mounted /system/\n");     
	        d1 = opendir(fstab1.c_str());
//	      if (d1 != NULL)
//	         gui_print ("DEBUG #4.2: Treble ROM - Opened directory\n");     
//	      else   
//	         gui_print ("DEBUG #4.3: Treble ROM - Cant Open\n");     
	        stat = 1;
	     }
        }
 
      if (d1 == NULL)
        {
	    gui_print ("OrangeFox: DM-Verity patch failed. Reboot OrangeFox and try again.\n");     
	    if (stat == 2)
		LOGINFO("Unable to open '%s'\n", fstab2.c_str());
	    else 
	    if (stat == 1)
		LOGINFO("Unable to open '%s'\n", fstab1.c_str());
	    return false;
        }
     
      while ((de = readdir(d1)) != NULL)
	{
	  usleep (32);
	  cmp = de->d_name;
	  
	  if (stat == 2)
	       path = fstab2 + "/" + cmp;
	  else 
	  if (stat == 1)
	     path = fstab1 + "/" + cmp;
	  
//gui_print ("DEBUG #6: filename=%s\n", path.c_str());     
	  if (cmp.find("fstab.") != string::npos)
	    {
	      gui_msg(Msg("of_fstab=Detected fstab: '{1}'") (cmp));
	      if (!status)
		{
		  if (
		     (TWFunc::CheckWord(path, "verify")) 
		  || (TWFunc::CheckWord(path, "support_scfs"))
		 // || (TWFunc::CheckWord(path, "avb"))
		  )
		    {
	               LOGINFO("OrangeFox: Relevant dm-verity settings are found in %s\n", path.c_str());
		       status = true;
		    } 
		    else
		    {
	               LOGINFO("OrangeFox: Relevant dm-verity settings are NOT found in %s\n", path.c_str());		    
		    }
		}
	      TWFunc::Replace_Word_In_File(path, remove);
	    }
	}
      closedir(d1);
      if (PartitionManager.Is_Mounted_By_Path("/system"))
	  PartitionManager.UnMount_By_Path("/system", false);
	
       if (PartitionManager.Is_Mounted_By_Path("/vendor"))
	  PartitionManager.UnMount_By_Path("/vendor", false);
    } // stat == 0

  if (TWFunc::Path_Exists(firmware_key))
    {
      if (!status)
	status = true;
      unlink(firmware_key.c_str());
    }
  LOGINFO("OrangeFox: leaving Patch_DM_Verity()\n");
  return status;
}

int TWFunc::Fstab_Has_Encryption_Flag(std::string path)
{
   if (
        (CheckWord(path, "forceencrypt")) 
     || (CheckWord(path, "forcefdeorfbe"))
     || (CheckWord(path, "fileencryption"))
     || (CheckWord(path, "errors=panic")) 
     || (CheckWord(path, "discard,"))
      )
        return 1;
   else
        return 0;
}

void TWFunc::Patch_Encryption_Flags(std::string path)
{
   TWFunc::Replace_Word_In_File(path,  "forcefdeorfbe=;forceencrypt=;fileencryption=;", "encryptable=");
   TWFunc::Remove_Word_From_File(path, "errors=panic");
   TWFunc::Remove_Word_From_File(path, "discard,");   
   /*
    TWFunc::Replace_Word_In_File(path, "forcefdeorfbe=;forceencrypt=;", "encryptable=");
    TWFunc::Replace_Word_In_File(path, "fileencryption=ice;", "encryptable=footer");
    */
}

bool TWFunc::Patch_Forced_Encryption()
{
  string path, cmp;
  int stat = 0;
  bool status = false;
  int encryption, treble;
  DataManager::GetValue(RW_DISABLE_DM_VERITY, encryption);
  DataManager::GetValue(FOX_ZIP_INSTALLER_TREBLE, treble);
  DIR *d;
  DIR *d1;
  struct dirent *de;
  
  LOGINFO("OrangeFox: entering Patch_Forced_Encyption()\n"); 
  d = opendir(ramdisk.c_str());
  if (d == NULL)
    {
      LOGINFO("Unable to open '%s'\n", ramdisk.c_str());
      return false;
    }

  //*** /tmp/orangefox/ramdisk/    
  while ((de = readdir(d)) != NULL)
    {
      usleep (32);
      cmp = de->d_name;
      path = ramdisk + "/" + cmp;
//gui_print ("DEBUG #21: filename=%s\n", path.c_str());     
      
      if (cmp.find("fstab.") != string::npos)
	{
	  if (encryption != 1)
	    {
	      gui_msg(Msg("of_fstab=Detected fstab: '{1}'") (cmp));
	      stat = 1;
	    }
	    
	  if (!status)
	    {
	      if (Fstab_Has_Encryption_Flag(path))
	      {  
		LOGINFO("OrangeFox: Relevant encryption settings are found in %s\n", path.c_str());
		status = true;
	      }
	      else
	      {
		 LOGINFO("OrangeFox: Relevant encryption settings are found in %s\n", path.c_str());
	      }
	    }
	    TWFunc::Patch_Encryption_Flags(path);
	}
    }
  closedir(d);  
  if (stat == 0)
  {
      d1 = NULL;

      if (treble == 1)
      {
//gui_print ("DEBUG #22: Treble ROM\n");     
         if (PartitionManager.Mount_By_Path("/vendor", false))      
	   {
//gui_print ("DEBUG #22.1: Treble ROM - Mounted /vendor.\n");     
	      d1 = opendir(fstab2.c_str());
//if (d1==NULL)
//gui_print ("DEBUG #22.2: Treble ROM - /vendor - failed to open directory: %s\n", fstab2.c_str());     

	      stat = 2;
	   }        
      } 

     if (d1 == NULL)
	{
//gui_print ("DEBUG #23: NULL - need to try again\n");     
	  if (PartitionManager.Mount_By_Path("/system", false))
	     {
//gui_print ("DEBUG #23.1: Mounted /system\n");     
	        d1 = opendir(fstab1.c_str());
//if (d1==NULL)
//gui_print ("DEBUG #23.2: Treble ROM - /system - failed to open directory: %s\n", fstab1.c_str());     
	        stat = 1;
	     }
        }
 
      if (d1 == NULL)
        {
	    gui_print ("OrangeFox: Forced-Encryption patch failed. Reboot OrangeFox and try again.\n");
	    if (stat == 2)
		LOGINFO("Unable to open '%s'\n", fstab2.c_str());
	    else 
	    if (stat == 1)
		LOGINFO("Unable to open '%s'\n", fstab1.c_str());
	    return false;
        }
           
      while ((de = readdir(d1)) != NULL)
	{
	  usleep (32);
	  cmp = de->d_name;
	  if (stat == 2)
 	       path = fstab2 + "/" + cmp;
	  else 
	  if (stat == 1)
	       path = fstab1 + "/" + cmp;
//gui_print ("DEBUG #25: filename=%s\n", path.c_str());	  
	  if (cmp.find("fstab.") != string::npos)
	    {
	      
	      if (encryption != 1)
		{
		  gui_msg(Msg("of_fstab=Detected fstab: '{1}'") (cmp));
		  stat = 1;
		}
	     
	     if (!status)
	        {
	          if (Fstab_Has_Encryption_Flag(path))
	          {
		      status = true;
		      LOGINFO("OrangeFox: Relevant encryption settings are found in %s\n", path.c_str());
		  } 
		  else
		  { 
		      LOGINFO("OrangeFox: Relevant encryption settings *NOT* found in %s\n", path.c_str());
		  }
	       }
	       TWFunc::Patch_Encryption_Flags(path);
	   }
	}
      closedir(d1);
     
       if (PartitionManager.Is_Mounted_By_Path("/system"))
    	      PartitionManager.UnMount_By_Path("/system", false);
    
       if (PartitionManager.Is_Mounted_By_Path("/vendor"))
    	      PartitionManager.UnMount_By_Path("/vendor", false);   	
  } // stat == 0   
  LOGINFO("OrangeFox: leaving Patch_Forced_Encyption()\n");
  return status;
}


void TWFunc::Patch_Others(void)
{
  std::string fstab = ramdisk + "/fstab.qcom";
  std::string default_prop = ramdisk + "/default.prop";
  std::string dm_verity_prop = "ro.config.dmverity";
  std::string result;
  std::string verity_key = ramdisk + "/verity_key";
  std::string firmware_key = ramdisk + "/sbin/firmware_key.cer";
  std::string debug = "ro.debuggable";
  std::string adb_ro = "ro.adb.secure";
  std::string ro = "ro.secure";
  std::string mock = "ro.allow.mock.location";
  std::string miui_secure_boot = "ro.secureboot.devicelock";
  std::string dm_verity_prop_false = dm_verity_prop + "=false";
  std::string dm_verity_prop_true = dm_verity_prop + "=true";

  // Enable ADB read-only property in the default.prop
  if (DataManager::GetIntValue(RW_ENABLE_ADB_RO) == 1)
    {
      TWFunc::Set_New_Ramdisk_Property(default_prop, adb_ro, true);
    }

  // Disable ADB read-only property in the default.prop
  if (DataManager::GetIntValue(RW_DISABLE_ADB_RO) == 1)
    {
      TWFunc::Set_New_Ramdisk_Property(default_prop, adb_ro, false);
    }

  // Enable read-only property in the default.prop
  if (DataManager::GetIntValue(RW_ENABLE_SECURE_RO) == 1)
    {
      TWFunc::Set_New_Ramdisk_Property(default_prop, ro, true);
    }

  // Disable read-only property in the default.prop
  if (DataManager::GetIntValue(RW_DISABLE_SECURE_RO) == 1)
    {
      TWFunc::Set_New_Ramdisk_Property(default_prop, ro, false);
    }

  // Disable secure-boot
  if (DataManager::GetIntValue(RW_DISABLE_SECURE_BOOT) == 1)
    {
      TWFunc::Set_New_Ramdisk_Property(default_prop, miui_secure_boot, false);
    }

  // Enable mock_location property
  if (DataManager::GetIntValue(RW_ENABLE_MOCK_LOCATION) == 1)
    {
      TWFunc::Set_New_Ramdisk_Property(default_prop, mock, true);
    }

  // Disable mock_location property
  if (DataManager::GetIntValue(RW_DISABLE_MOCK_LOCATION) == 1)
    {
      TWFunc::Set_New_Ramdisk_Property(default_prop, mock, false);
    }

  // Set permissions
  if (Path_Exists(default_prop)) 
  	chmod(default_prop.c_str(), 0644);

  if (Path_Exists(fstab)) 
  	chmod(fstab.c_str(), 0640);
}


void TWFunc::Deactivation_Process(void)
{
 
  Fox_Zip_Installer_Code = DataManager::GetIntValue(FOX_ZIP_INSTALLER_CODE);
  usleep(16);

  Fox_Force_Deactivate_Process = DataManager::GetIntValue(FOX_FORCE_DEACTIVATE_PROCESS);
  usleep(16);

  // increment value, to show how many times we have called this
  Fox_IsDeactivation_Process_Called++;

  // Check AromaFM Config
  if (
     (DataManager::GetIntValue(RW_SAVE_LOAD_AROMAFM) == 1)
  && (PartitionManager.Mount_By_Path("/sdcard", false))
     )
    {
      string aromafm_path = Fox_Home;
      string aromafm_file = aromafm_path + "/aromafm.cfg";
      if (!Path_Exists(aromafm_path))
	{
	  if (mkdir
	      (aromafm_path.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH))
	    {
	      LOGERR("Error making %s directory: %s\n", aromafm_path.c_str(), strerror(errno));
	    }
	}
      // Save AromaFM config (AromaFM.cfg)
      if (copy_file(FFiles_dir + "/AromaFM/AromaFM.zip.cfg", aromafm_file, 0644))
	{
	  LOGERR("Error copying AromaFM config\n");
	}
      PartitionManager.UnMount_By_Path("/sdcard", false);
    }

  // advanced stock replace
  Disable_Stock_Recovery_Replace();

  // restore the stock recovery ?
  if (
     (DataManager::GetIntValue(RW_DONT_REPLACE_STOCK) == 1)
  && (PartitionManager.Mount_By_Path("/system", false))
     )
    {
      if (Path_Exists("/system/wlfx0recovery-from-boot.bak0xwlf"))
	{
	  rename("/system/wlfx0recovery-from-boot.bak0xwlf",
		 "/system/recovery-from-boot.p");
	}
      PartitionManager.UnMount_By_Path("/system", false);
    }

  // unpack boot image
  if (!Unpack_Image("/boot"))
     {
	LOGINFO("Deactivation_Process: Unable to unpack boot image\n");
	return;
     }

  gui_msg(Msg(msg::kProcess, "of_run_process=Starting '{1}' process")
      ("OrangeFox"));
 
  // dm-verity 
  if ((DataManager::GetIntValue(RW_DISABLE_DM_VERITY) == 1) || (Fox_Force_Deactivate_Process == 1))
     {
	  if (Patch_DM_Verity())
	  {
              DataManager::SetValue(RW_DISABLE_FORCED_ENCRYPTION, 1);
	      gui_msg("of_dm_verity=Successfully patched DM-Verity");
	  }
	  else
	      gui_msg("of_dm_verity_off=DM-Verity is not enabled");
     }

  // forced encryption    
  if ((DataManager::GetIntValue(RW_DISABLE_FORCED_ENCRYPTION) == 1) || (Fox_Force_Deactivate_Process == 1))
     {
	  if (Patch_Forced_Encryption())
	       gui_msg("of_encryption=Successfully patched forced encryption");
	  else
	       gui_msg("of_encryption_off=Forced Encryption is not enabled");
     }

  // other stuff
  Patch_Others();

  // repack the boot image
  if (!Repack_Image("/boot"))
     {
	gui_msg(Msg
	  (msg::kProcess, "of_run_process_fail=Unable to finish '{1}' process")
	  ("OrangeFox"));
     }
  else
       gui_msg(Msg(msg::kProcess, "of_run_process_done=Finished '{1}' process")
	  ("OrangeFox"));

  // reset "force" stuff  
  Fox_Force_Deactivate_Process = 0;
  DataManager::SetValue(FOX_FORCE_DEACTIVATE_PROCESS, 0);
}

#endif // ifndef BUILD_TWRPTAR_MAIN
