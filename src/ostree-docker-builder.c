/* -*- mode: C; c-file-style: "gnu"; indent-tabs-mode: nil; -*-
 *
 * Copyright (C) 2015 Giuseppe Scrivano <giuseppe@scrivano.org>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 *
 * Author: Giuseppe Scrivano <giuseppe@scrivano.org>
 */

#include <config.h>

#include <libglnx.h>
#include <ostree.h>
#include <libgsystem.h>
#include <archive.h>
#include <archive_entry.h>
#include <stdio.h>
#include <gio/gunixinputstream.h>

#define QUERY ("standard::name,standard::type,standard::size,standard::is-symlink,standard::symlink-target," \
               "unix::device,unix::inode,unix::mode,unix::uid,unix::gid,unix::rdev,time::modified")

static struct archive *a;

//TODO: move into a context structure
GPtrArray *g_modified;
GPtrArray *g_removed;
GPtrArray *g_added;

//TODO: remove it...
static const char *skip_list[] = {
  "/lib",
  "/boot",
  "/proc",
  "/usr/lib/modules",
  "/usr/lib/firmware",
  "/usr/lib/grub",
  };

static gboolean
is_skip (GFile *f)
{
  int i;
  const char *file = gs_file_get_path_cached (f);
  for (i = 0; i < sizeof (skip_list) / sizeof (skip_list[0]); i++)
    {
      if (strncmp (file, skip_list[i], strlen (file)) == 0)
        return TRUE;
    }
  return FALSE;
}

static gboolean
write_to_archive (GFile *f, GFileInfo *info, GError **error)
{
  const char *filename = gs_file_get_path_cached (f);
  struct archive_entry *entry;
  struct stat st;
  char buff[8192];
  int len;
  GInputStream *is;
  gboolean ret = FALSE;
  g_autoptr(GFileInputStream) file_input = NULL;

  //FIXME: use a table instead of iterating g_added.
  if (g_added)
    {
      guint i;
      gboolean found = FALSE;
      for (i = 0; i < g_added->len && !found; i++)
        {
          found = g_file_equal (f, g_added->pdata[i]) || g_file_has_prefix (f, g_added->pdata[i]);
        }
      for (i = 0; i < g_modified->len && !found; i++)
        {
          OstreeDiffItem *diff = g_modified->pdata[i];
          found = g_file_equal (f, diff->target) || g_file_has_prefix (f, diff->target);
        }
      if (!found)
        return TRUE;
    }

  printf ("Writing: %s\n", filename);

  entry = archive_entry_new ();
  if (!entry)
    return FALSE;

  archive_entry_set_pathname (entry, filename);

  archive_entry_set_perm (entry, g_file_info_get_attribute_uint32 (info, "unix::mode"));
  archive_entry_set_uid (entry, g_file_info_get_attribute_uint32 (info, "unix::uid"));
  archive_entry_set_gid (entry, g_file_info_get_attribute_uint32 (info, "unix::gid"));
  {
    guint64 mtime = g_file_info_get_attribute_uint64 (info, "time::modified");
    archive_entry_set_mtime (entry, mtime >> 32, mtime & 0xFFFFFFFF);
  }

  if (g_file_info_get_file_type (info) == G_FILE_TYPE_SYMBOLIC_LINK)
    {
      archive_entry_set_symlink (entry, g_file_info_get_attribute_byte_string (info, "standard::symlink-target"));
      archive_entry_set_filetype (entry, AE_IFLNK);
    }
  else if (g_file_info_get_file_type (info) == G_FILE_TYPE_DIRECTORY)
    {
      archive_entry_set_filetype (entry, AE_IFDIR);
    }
  else
    {
      archive_entry_set_size (entry, g_file_info_get_size (info));
      archive_entry_set_filetype (entry, AE_IFREG);
    }

  {
    GVariant *xattrs;
    int i, n;

    if (!ostree_repo_file_get_xattrs ((OstreeRepoFile*) f, &xattrs, NULL, NULL))
      return FALSE;

    n = g_variant_n_children (xattrs);
    for (i = 0; i < n; i++)
      {
        const guint8* name;
        const guint8* value_data;
        g_autoptr(GVariant) value = NULL;
        gsize value_len;

        g_variant_get_child (xattrs, i, "(^&ay@ay)", &name, &value);
        value_data = g_variant_get_fixed_array (value, &value_len, 1);
        archive_entry_xattr_add_entry (entry, name, value_data, value_len);
      }
    g_variant_unref (xattrs);
  }

  if (archive_write_header (a, entry) < 0)
    return FALSE;

  if (g_file_info_get_file_type (info) == G_FILE_TYPE_REGULAR)
    {
      file_input = g_file_read (f, NULL, error);
      if (file_input == NULL)
        goto out;

      is = G_INPUT_STREAM (file_input);
      while (TRUE)
        {
          gssize read = g_input_stream_read (is,
                                             buff,
                                             sizeof (buff),
                                             NULL,
                                             NULL);
          if (read == 0)
            break;

          if (archive_write_data (a, buff, read) < 0)
            goto out;
        }
    }
  ret = TRUE;
  archive_entry_free (entry);
 out:
  return ret;
}

static gboolean
scan_one_file (GFile     *f,
               GFileInfo *file_info,
               GError  **error)
{
  if (g_file_info_get_file_type (file_info) == G_FILE_TYPE_REGULAR ||
      g_file_info_get_file_type (file_info) == G_FILE_TYPE_SYMBOLIC_LINK)
    {
      return write_to_archive (f, file_info, error);
    }

  return TRUE;
}

static gboolean
scan_directory_recurse (GFile    *f,
                        GFileInfo *info,
                        int       depth,
                        GError  **error)
{
  gboolean ret = FALSE;
  g_autoptr(GFileEnumerator) dir_enum = NULL;
  g_autoptr(GFile) child = NULL;
  g_autoptr(GFileInfo) child_info = NULL;
  GError *temp_error = NULL;

  if (depth > 0)
    depth--;
  else if (depth == 0)
    return TRUE;
  else
    g_assert (depth == -1);

  if (is_skip (f))
    return TRUE;

  dir_enum = g_file_enumerate_children (f, QUERY,
                                        G_FILE_QUERY_INFO_NOFOLLOW_SYMLINKS,
                                        NULL,
                                        error);
  if (!dir_enum)
    goto out;

  while ((child_info = g_file_enumerator_next_file (dir_enum, NULL, &temp_error)) != NULL)
    {
      g_clear_object (&child);
      child = g_file_get_child (f, g_file_info_get_name (child_info));

      if (!scan_one_file (child, child_info, error))
        goto out;

      if (g_file_info_get_file_type (child_info) == G_FILE_TYPE_DIRECTORY)
        {
          if (!scan_directory_recurse (child, child_info, depth, error))
            goto out;
        }

      g_clear_object (&child_info);
    }
  if (temp_error)
    {
      g_propagate_error (error, temp_error);
      goto out;
    }

  ret = TRUE;
 out:
  return ret;
}

static gboolean
find_parent_image (OstreeRepo *repo, const char *checksum, char **out_parent, char **out_parent_image, GError **error)
{
  int pipes[2];
  g_autoptr(GVariant) commit = NULL;
  gchar *parent, *parent_image;
  pid_t pid;
  if (!ostree_repo_load_commit (repo, checksum, &commit, NULL, error))
    goto out;

  parent = ostree_commit_get_parent (commit);
  if (!parent)
    return NULL;

  if (pipe (pipes) < 0)
    goto out;

  pid = fork ();
  if (pid < 0)
    goto out;

  if (pid == 0)
    {
      char label_selector[512];
      close (pipes[0]);
      dup2 (pipes[1], 1);
      sprintf (label_selector, "label=ostree.commit=%s", parent);
      execl ("/usr/bin/docker", "/usr/bin/docker", "images", "--no-trunc=true", "--filter", label_selector, NULL);
      _exit (1);
    }
  else
    {
      int i;
      char buffer[4096], *it;
      gsize read;
      g_autoptr(GInputStream) input_stream = g_unix_input_stream_new (pipes[0], TRUE);

      close (pipes[1]);
      if (g_input_stream_read_all (input_stream, buffer, sizeof (buffer) - 1, &read, NULL, error) < 0)
        goto out;

      buffer[read] = '\0';
      it = strchr (buffer, '\n');
      if (it == NULL)
        goto out;

      it++;
      for (i = 0; i < 2; i++)
        {
          it = strchr (it, ' ');
          if (it == NULL)
            goto out;

          it += strspn (it, " ");
        }

      parent_image = it;
      it = strchr (it, ' ');
      if (it)
        *it = '\0';

      if (out_parent)
        *out_parent = g_strdup (parent);
      if (out_parent_image)
        *out_parent_image = g_strdup (parent_image);
    }

  return TRUE;
 out:
  return FALSE;
}

static gboolean
write_full_content (OstreeRepo *repo, const char *checksum, GError **error)
{
  gboolean ret = FALSE;
  g_autoptr(GFile) root = NULL;
  g_autoptr(GFile) f = NULL;
  g_autoptr(GFileInfo) file_info = NULL;
  const char *root_path = "/";
  if (!ostree_repo_read_commit (repo, checksum, &root, NULL, NULL, error))
    goto out;

  f = g_file_resolve_relative_path (root, root_path);

  file_info = g_file_query_info (f, QUERY,
                                 G_FILE_QUERY_INFO_NOFOLLOW_SYMLINKS,
                                 NULL, error);
  if (!file_info)
    goto out;

  if (! write_to_archive (f, file_info, error))
    goto out;

  if (g_file_info_get_file_type (file_info) == G_FILE_TYPE_DIRECTORY)
    {
      if (!scan_directory_recurse (f, file_info, -1, error))
        goto out;
    }

  ret = TRUE;

 out:
  return ret;
}

static gboolean
do_diff (OstreeRepo *repo, const char *checksum, const char *parent, GPtrArray *modified,
         GPtrArray *removed, GPtrArray *added, GError **error)
{
  g_autoptr(GFile) a = NULL;
  g_autoptr(GFile) b = NULL;

  if (!ostree_repo_read_commit (repo, checksum, &a, NULL, NULL, error))
    goto out;

  if (!ostree_repo_read_commit (repo, parent, &b, NULL, NULL, error))
    goto out;

  return ostree_diff_dirs (OSTREE_DIFF_FLAGS_NONE, a, b, modified, removed, added, NULL, error);

 out:
  return FALSE;
}

static gboolean
write_dockerfile_to_archive (const char *container_name, const char *checksum, const char *image, GError **error)
{
  struct archive_entry *entry;
  gboolean ret = FALSE;
  g_autofree gchar *buf;
  guint i;
  g_autofree gchar *remove_list = NULL;
  GString *remove_buf = g_string_new ("");

  entry = archive_entry_new ();
  if (!entry)
    return FALSE;

  if (image == NULL)
    image = "scratch";

  for (i = 0; i < g_removed->len; i++)
    {
      GFile *file = g_removed->pdata[i];
      const char *filename = gs_file_get_path_cached (file);
      if (!is_skip (file))
        {
          g_string_append (remove_buf, " \"");
          g_string_append (remove_buf, filename);
          g_string_append_c (remove_buf, '\"');
        }
    }
  for (i = 0; i < g_modified->len; i++)
    {
      OstreeDiffItem *diff = g_modified->pdata[i];
      const char *from = gs_file_get_path_cached (diff->src);

      if (!is_skip (diff->src))
        {
          g_string_append (remove_buf, " \"");
          g_string_append (remove_buf, from);
          g_string_append_c (remove_buf, '\"');
        }
    }

  remove_list = g_string_free (remove_buf, FALSE);

  buf = g_strdup_printf ("FROM %s@%s\nRUN rm -rf %s\nADD * /\nRUN rm -rf /Dockerfile\nLABEL ostree.commit=%s\n", container_name, image, remove_list, checksum);

  archive_entry_set_pathname (entry, "/Dockerfile");
  archive_entry_set_filetype (entry, AE_IFREG);
  archive_entry_set_size (entry, strlen (buf));

  if (archive_write_header (a, entry) < 0)
    goto out;

  if (archive_write_data (a, buf, strlen (buf)) < 0)
   goto out;

  ret = TRUE;
 out:
  archive_entry_free (entry);
  return ret;
}

int
main (int argc, const char **argv)
{
  int fd[2], pid;
  GError *error = NULL;
  glnx_unref_object OstreeRepo *repo = NULL;
  glnx_unref_object GFile *repopath = NULL;
  const char *container_name;
  const char *checksum;
  const static gboolean write_to_file = FALSE;
  g_autofree char *parent_image = NULL;
  const gboolean debug_diff = FALSE;

  if (argc < 4)
    {
      fprintf (stderr, "Usage %s REPO IMAGE_NAME COMMIT_ID\n", argv[0]);
      goto out;
    }

  container_name = argv[2];
  checksum = argv[3];

  {
    struct sigaction sa;
    sa.sa_handler = SIG_IGN;
    sa.sa_flags = 0;
    if (sigaction (SIGPIPE, &sa, 0) == -1)
      {
        goto out;
      }
  }

  if (!write_to_file)
    {
      if (getuid ())
        {
          fprintf (stderr, "You need to be root\n");
          goto out;
        }

      if (pipe (fd))
        goto out;
      pid = fork ();
      if (pid < 0)
        goto out;
      if (pid == 0)
        {
          dup2 (fd[0], 0);
          close (fd[0]);
          close (fd[1]);
          execl ("/usr/bin/docker", "/usr/bin/docker", "build", "-t", container_name, "-", NULL);
          _exit (1);
        }
        close (fd[0]);
    }
  repopath = g_file_new_for_path (argv[1]);
  repo = ostree_repo_new (repopath);
  if (!ostree_repo_open (repo, NULL, &error))
    goto out;

  a = archive_write_new ();
  archive_write_add_filter_gzip (a);
  archive_write_set_format_pax (a);
  archive_write_set_format_gnutar (a);
  if (write_to_file)
    archive_write_open_filename (a, "output.tar");
  else
    archive_write_open_fd (a, fd[1]);

  {
    g_autofree char *parent = NULL;

    if (find_parent_image (repo, checksum, &parent, &parent_image, &error))
      {
        guint i;

        g_modified = g_ptr_array_new_with_free_func ((GDestroyNotify) ostree_diff_item_unref);
        g_removed = g_ptr_array_new_with_free_func ((GDestroyNotify) g_object_unref);
        g_added = g_ptr_array_new_with_free_func ((GDestroyNotify) g_object_unref);

        if (!do_diff (repo, parent, checksum, g_modified, g_removed, g_added, &error))
          goto out;

        if (debug_diff)
          {
            for (i = 0; i < g_added->len; i++)
              {
                GFile *file = g_added->pdata[i];
                const char *filename = g_strdup (gs_file_get_path_cached (file));
                printf ("ADDED %s\n", filename);
              }
            for (i = 0; i < g_removed->len; i++)
              {
                GFile *file = g_removed->pdata[i];
                const char *filename = gs_file_get_path_cached (file);
                printf ("REMOVED %s\n", filename);
              }
            for (i = 0; i < g_modified->len; i++)
              {
                OstreeDiffItem *diff = g_modified->pdata[i];
                const char *from = gs_file_get_path_cached (diff->src);
                const char *to = gs_file_get_path_cached (diff->target);
                printf ("MODIFIED %s -> %s\n", from, to);
              }
          }
      }
  }

  if (!write_dockerfile_to_archive (container_name, checksum, parent_image, &error))
    goto out;

  if (!write_full_content (repo, checksum, &error))
    goto out;

  archive_write_close (a);
  archive_write_free (a);

  return 0;

 out:
  //FIXME: properly report all errors
  if (error)
    fprintf (stderr, "error: %s\n", error->message);
  return -1;
}
