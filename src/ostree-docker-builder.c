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

static gchar *opt_repo;
static gchar *opt_container_name;
static gchar *opt_maintainer;
static gchar *opt_entrypoint;
static gchar *opt_filename;
static gchar **opt_extra_directives;
static gboolean opt_nolabel_commit;
static gboolean opt_debug_diff;

static GOptionEntry entries[] =
{
  { "container-name", 'c', 0, G_OPTION_ARG_STRING, &opt_container_name, "Container name", NULL },
  { "debug-diff", 'D', 0, G_OPTION_ARG_NONE, &opt_debug_diff, "Dump additional files diff information", NULL },
  { "directive", 'd', 0, G_OPTION_ARG_STRING_ARRAY, &opt_extra_directives, "Specify extra directives for the Dockerfile", NULL },
  { "entrypoint", 'e', 0, G_OPTION_ARG_STRING, &opt_entrypoint, "Specify the entrypoint", NULL },
  { "filename", 'f', 0, G_OPTION_ARG_STRING, &opt_filename, "If specified, write to this tar file instead", NULL },
  { "maintainer", 'm', 0, G_OPTION_ARG_STRING, &opt_maintainer, "Specify the maintainer", NULL },
  { "no-label-commit", 'l', 0, G_OPTION_ARG_NONE, &opt_nolabel_commit, "Do not add an ostree.commit label", NULL },
  { "repo", 'r', 0, G_OPTION_ARG_FILENAME, &opt_repo, "OStree repository location", NULL },
  { NULL }
};

#define QUERY ("standard::name,standard::type,standard::size,standard::is-symlink,standard::symlink-target," \
               "unix::device,unix::inode,unix::mode,unix::uid,unix::gid,unix::rdev,time::modified")

struct BuilderContext
{
  OstreeRepo *repo;
  struct archive *archive;

  GPtrArray *modified;
  GPtrArray *removed;
  GPtrArray *added;
};

typedef struct BuilderContext *BuilderContextPtr;

static gboolean
mkdir_to_archive (struct archive *archive, const char *dir, mode_t mode, uid_t uid, gid_t gid)
{
  gboolean ret = FALSE;
  struct archive_entry *entry = archive_entry_new ();
  g_assert (entry);

  archive_entry_set_pathname (entry, dir);
  archive_entry_set_perm (entry, mode);
  archive_entry_set_uid (entry, uid);
  archive_entry_set_gid (entry, gid);
  archive_entry_set_filetype (entry, AE_IFDIR);
  if (archive_write_header (archive, entry) < 0)
    goto out;

  ret = TRUE;

 out:
  archive_entry_free (entry);
  return ret;
}

static gboolean
write_to_archive (BuilderContextPtr ctx, GFile *f, GFileInfo *info, GError **error)
{
  g_autofree gchar *filename = NULL;
  struct archive_entry *entry;
  struct stat st;
  int len;
  GInputStream *is;
  gboolean ret = FALSE;
  g_autoptr(GFileInputStream) file_input = NULL;

  if (ctx->added)
    {
      guint i;
      gboolean found = FALSE;
      for (i = 0; i < ctx->added->len && !found; i++)
        {
          found = g_file_equal (f, ctx->added->pdata[i]) || g_file_has_prefix (f, ctx->added->pdata[i]);
        }
      for (i = 0; i < ctx->modified->len && !found; i++)
        {
          OstreeDiffItem *diff = ctx->modified->pdata[i];
          found = g_file_equal (f, diff->target) || g_file_has_prefix (f, diff->target);
        }
      if (!found)
        return TRUE;
    }

  entry = archive_entry_new ();
  if (!entry)
    return FALSE;

  filename = g_strdup_printf ("/sysroot%s", gs_file_get_path_cached (f));
  printf ("Writing: %s\n", gs_file_get_path_cached (f));
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

  if (archive_write_header (ctx->archive, entry) < 0)
    return FALSE;

  if (g_file_info_get_file_type (info) == G_FILE_TYPE_REGULAR)
    {
      g_autofree gchar *buf = NULL;
      const size_t BUF_SIZE = 8192;
      file_input = g_file_read (f, NULL, error);
      if (file_input == NULL)
        goto out;

      buf = g_new0 (gchar, BUF_SIZE);
      is = G_INPUT_STREAM (file_input);
      while (TRUE)
        {
          gssize read = g_input_stream_read (is,
                                             buf,
                                             BUF_SIZE,
                                             NULL,
                                             NULL);
          if (read == 0)
            break;

          if (archive_write_data (ctx->archive, buf, read) < 0)
            goto out;
        }
    }
  ret = TRUE;
  archive_entry_free (entry);
 out:
  return ret;
}

static gboolean
scan_one_file (BuilderContextPtr ctx,
               GFile             *f,
               GFileInfo         *file_info,
               GError            **error)
{
  if (g_file_info_get_file_type (file_info) == G_FILE_TYPE_REGULAR ||
      g_file_info_get_file_type (file_info) == G_FILE_TYPE_SYMBOLIC_LINK)
    {
      return write_to_archive (ctx, f, file_info, error);
    }

  return TRUE;
}

static gboolean
scan_directory_recurse (BuilderContextPtr ctx,
                        GFile    *f,
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

      if (!scan_one_file (ctx, child, child_info, error))
        goto out;

      if (g_file_info_get_file_type (child_info) == G_FILE_TYPE_DIRECTORY)
        {
          if (!scan_directory_recurse (ctx, child, child_info, depth, error))
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
find_parent_image (BuilderContextPtr ctx, const char *checksum, char **out_parent, char **out_parent_image, GError **error)
{
  int pipes[2];
  g_autoptr(GVariant) commit = NULL;
  gchar *parent, *parent_image;
  pid_t pid;
  if (!ostree_repo_load_commit (ctx->repo, checksum, &commit, NULL, error))
    goto out;

  *out_parent = *out_parent_image = NULL;
  parent = ostree_commit_get_parent (commit);
  if (!parent)
    return TRUE;

  if (pipe (pipes) < 0)
    goto out_set_error_from_errno;

  pid = fork ();
  if (pid < 0)
    goto out_set_error_from_errno;

  if (pid == 0)
    {
      int dev_null = open ("/dev/null", O_RDWR);
      char label_selector[512];
      if (close (pipes[0]) < 0)
        _exit (1);
      if (dup2 (dev_null, 1) < 0)
        _exit (1);
      if (dup2 (dev_null, 2) < 0)
        _exit (1);
      close (dev_null);
      if (dup2 (pipes[1], 1) < 0)
        _exit (1);
      sprintf (label_selector, "label=ostree.commit=%s", parent);
      execl ("/usr/bin/docker", "/usr/bin/docker", "images", "--no-trunc=true", "--filter", label_selector, NULL);
      _exit (1);
    }
  else
    {
      int status = 0;
      int i;
      g_autofree gchar *buf = NULL;
      gchar *it;
      gsize read;
      const size_t BUF_SIZE = 4096;
      g_autoptr(GInputStream) input_stream = g_unix_input_stream_new (pipes[0], TRUE);

      close (pipes[1]);
      buf = g_new0 (gchar, BUF_SIZE);
      if (g_input_stream_read_all (input_stream, buf, BUF_SIZE - 1, &read, NULL, error) < 0)
        goto out;

      buf[read] = '\0';
      it = strchr (buf, '\n');
      if (it == NULL)
        {
          g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_FAILED, "Could not parse Docker output");
          goto out;
        }

      it++;
      for (i = 0; i < 2; i++)
        {
          it = strchr (it, ' ');
          if (it == NULL)
            {
              g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_FAILED, "Could not parse Docker output");
              goto out;
            }

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

      if (close (pipes[0]) < 0)
        goto out_set_error_from_errno;

      if (waitpid (pid, &status, 0) < 0)
        {
          goto out_set_error_from_errno;
          if (!WIFEXITED (status) || WEXITSTATUS (status))
            {
              g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                                   "The Docker process exited with an error");
              goto out;
            }
        }
    }

  return TRUE;

 out_set_error_from_errno:
  gs_set_error_from_errno (error, errno);

 out:
  return FALSE;
}

static gboolean
write_full_content (BuilderContextPtr ctx, const char *checksum, GError **error)
{
  gboolean ret = FALSE;
  g_autoptr(GFile) root = NULL;
  g_autoptr(GFile) f = NULL;
  g_autoptr(GFileInfo) file_info = NULL;
  const char *root_path = "/";
  if (!ostree_repo_read_commit (ctx->repo, checksum, &root, NULL, NULL, error))
    goto out;

  f = g_file_resolve_relative_path (root, root_path);

  file_info = g_file_query_info (f, QUERY,
                                 G_FILE_QUERY_INFO_NOFOLLOW_SYMLINKS,
                                 NULL, error);
  if (!file_info)
    goto out;

  if (!mkdir_to_archive (ctx->archive, "/sysroot", 0777, 0, 0))
    goto out;

  if (!write_to_archive (ctx, f, file_info, error))
    goto out;

  if (g_file_info_get_file_type (file_info) == G_FILE_TYPE_DIRECTORY)
    {
      if (!scan_directory_recurse (ctx, f, file_info, -1, error))
        goto out;
    }

  ret = TRUE;

 out:
  return ret;
}

static gboolean
do_diff (OstreeRepo *repo, const gchar *checksum, const gchar *parent, GPtrArray *modified,
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
write_dockerfile_to_archive (BuilderContextPtr ctx, const gchar *container_name, const gchar *checksum,
                             const gchar *image, const gchar *maintainer, const gchar *entrypoint,
                             gboolean nolabel_commit, gchar * const *directives, GError **error)
{
  struct archive_entry *entry;
  gboolean ret = FALSE;
  g_autofree gchar *buf = NULL;
  g_autofree gchar *image_name = NULL;
  guint i;
  g_autofree gchar *remove_list = NULL;
  g_autofree gchar *dockerfile = NULL;
  GString *remove_buf = g_string_new ("");
  GString *dockerfile_buf = g_string_new ("");

  entry = archive_entry_new ();
  g_assert (entry);

  if (image == NULL)
    image_name = g_strdup ("scratch");
  else
    image_name = g_strdup_printf ("%s@%s", container_name, image);

  if (ctx->removed)
    for (i = 0; i < ctx->removed->len; i++)
      {
        GFile *file = ctx->removed->pdata[i];
        const char *filename = gs_file_get_path_cached (file);
        g_string_append (remove_buf, " \"");
        g_string_append (remove_buf, filename);
        g_string_append_c (remove_buf, '\"');
      }

  if (ctx->modified)
    for (i = 0; i < ctx->modified->len; i++)
      {
        OstreeDiffItem *diff = ctx->modified->pdata[i];
        const char *from = gs_file_get_path_cached (diff->src);
        g_string_append (remove_buf, " \"");
        g_string_append (remove_buf, from);
        g_string_append_c (remove_buf, '\"');
      }

  remove_list = g_string_free (remove_buf, FALSE);

  g_string_append_printf (dockerfile_buf, "FROM %s\n", image_name);
  if (maintainer)
    g_string_append_printf (dockerfile_buf, "MAINTAINER %s\n", maintainer);

  if (remove_list[0])
      g_string_append_printf (dockerfile_buf, "RUN rm -rf %s\n", remove_list);

  g_string_append (dockerfile_buf, "ADD sysroot /\n");

  if (!nolabel_commit)
    g_string_append_printf (dockerfile_buf, "LABEL ostree.commit=%s\n", checksum);

  if (directives)
    for (i = 0; directives[i]; i++)
      g_string_append_printf (dockerfile_buf, "%s\n", directives[i]);

  if (entrypoint)
    g_string_append_printf (dockerfile_buf, "ENTRYPOINT %s\n", entrypoint);

  dockerfile = g_string_free (dockerfile_buf, FALSE);

  archive_entry_set_pathname (entry, "/Dockerfile");
  archive_entry_set_filetype (entry, AE_IFREG);
  archive_entry_set_size (entry, strlen (dockerfile));

  if (archive_write_header (ctx->archive, entry) < 0)
    goto out;

  if (archive_write_data (ctx->archive, dockerfile, strlen (dockerfile)) < 0)
   goto out;

  ret = TRUE;
 out:
  archive_entry_free (entry);
  return ret;
}

int
main (int argc, char *argv[])
{
  int fd[2];
  pid_t pid = -1;
  GError *error = NULL;
  glnx_unref_object OstreeRepo *repo = NULL;
  glnx_unref_object GFile *repopath = NULL;
  g_autofree char *checksum = NULL;
  g_autofree char *parent_image = NULL;
  struct BuilderContext ctx;

  GOptionContext *context;

  context = g_option_context_new ("COMMIT");
  g_option_context_add_main_entries (context, entries, "ostree-docker-builder");

  if (!g_option_context_parse (context, &argc, &argv, &error))
    {
      g_print ("option parsing failed: %s\n", error->message);
      goto out;
    }

  if (!opt_repo)
    {
      fprintf (stderr, "No repo specified\n");
      goto out;
    }
  if (!opt_container_name)
    {
      fprintf (stderr, "No container name specified\n");
      goto out;
    }

  if (argc == 0)
    {
      fprintf (stderr, "No commit specified\n");
      goto out;
    }

  {
    struct sigaction sa;
    sa.sa_handler = SIG_IGN;
    sa.sa_flags = 0;
    if (sigaction (SIGPIPE, &sa, 0) == -1)
      {
        goto out;
      }
  }

  if (!opt_filename)
    {
      if (getuid ())
        {
          fprintf (stderr, "You need to be root\n");
          goto out;
        }
    }
  repopath = g_file_new_for_path (opt_repo);
  repo = ostree_repo_new (repopath);
  if (!ostree_repo_open (repo, NULL, &error))
    goto out;

  if (!ostree_repo_resolve_rev (repo,
                                argv[1],
                                FALSE,
                                &checksum,
                                &error))
    goto out;

  memset (&ctx, 0, sizeof (ctx));
  ctx.repo = repo;

  {
    g_autofree char *parent = NULL;

    if (find_parent_image (&ctx, checksum, &parent, &parent_image, &error))
      {
        guint i;

        ctx.modified = g_ptr_array_new_with_free_func ((GDestroyNotify) ostree_diff_item_unref);
        ctx.removed = g_ptr_array_new_with_free_func ((GDestroyNotify) g_object_unref);
        ctx.added = g_ptr_array_new_with_free_func ((GDestroyNotify) g_object_unref);

        if (!do_diff (repo, parent, checksum, ctx.modified, ctx.removed, ctx.added, &error))
          goto out;

        if (opt_debug_diff)
          {
            for (i = 0; i < ctx.added->len; i++)
              {
                GFile *file = ctx.added->pdata[i];
                const char *filename = g_strdup (gs_file_get_path_cached (file));
                printf ("ADDED %s\n", filename);
              }
            for (i = 0; i < ctx.removed->len; i++)
              {
                GFile *file = ctx.removed->pdata[i];
                const char *filename = gs_file_get_path_cached (file);
                printf ("REMOVED %s\n", filename);
              }
            for (i = 0; i < ctx.modified->len; i++)
              {
                OstreeDiffItem *diff = ctx.modified->pdata[i];
                const char *from = gs_file_get_path_cached (diff->src);
                const char *to = gs_file_get_path_cached (diff->target);
                printf ("MODIFIED %s -> %s\n", from, to);
              }
          }
      }
  }

  if (!opt_filename)
    {
      if (pipe (fd))
        goto out_set_error_from_errno;
      pid = fork ();
      if (pid < 0)
        goto out_set_error_from_errno;
      if (pid == 0)
        {
          int dev_null = open ("/dev/null", O_RDWR);
          if (dup2 (fd[0], 0) < 0)
            _exit (1);
          if (dup2 (dev_null, 1) < 0)
            _exit (1);
          if (dup2 (dev_null, 2) < 0)
            _exit (1);
          close (dev_null);
          if (close (fd[0]) < 0)
            _exit (1);
          if (close (fd[1]) < 0)
            _exit (1);
          execl ("/usr/bin/docker", "/usr/bin/docker", "build", "-t", opt_container_name, "-", NULL);
          _exit (1);
        }
      close (fd[0]);
    }

  ctx.archive = archive_write_new ();
  archive_write_add_filter_gzip (ctx.archive);
  archive_write_set_format_pax (ctx.archive);
  archive_write_set_format_gnutar (ctx.archive);
  if (opt_filename)
    archive_write_open_filename (ctx.archive, opt_filename);
  else
    archive_write_open_fd (ctx.archive, fd[1]);

  if (!write_dockerfile_to_archive (&ctx, opt_container_name, checksum, parent_image,
                                    opt_maintainer, opt_entrypoint, opt_nolabel_commit,
                                    opt_extra_directives, &error))
    goto out;

  if (!write_full_content (&ctx, checksum, &error))
    goto out;

  if (archive_write_close (ctx.archive) < 0)
    goto out_set_error_from_errno;
  archive_write_free (ctx.archive);

  if (pid >= 0)
    {
      int status = 0;
      if (waitpid (pid, &status, 0) < 0)
        goto out_set_error_from_errno;
      if (!WIFEXITED (status) || WEXITSTATUS (status))
        {
          g_set_error_literal (&error, G_IO_ERROR, G_IO_ERROR_FAILED,
                               "The Docker process exited with an error");
          goto out;
        }
    }

  return 0;

 out_set_error_from_errno:
  gs_set_error_from_errno (&error, errno);
 out:
  g_assert (error);
  if (error)
    fprintf (stderr, "error: %s\n", error->message);
  return -1;
}
