#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>
#include <grp.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <time.h>
#include <zlib.h>
#include <sys/types.h>
#include <pwd.h>
#include <string.h>

#include "viktar.h"

# define BUFFER_LEN 2000

// Function declaration
void show_help_text_and_exit(void);

int main
(int argc, char *argv[]){

    ///MEMEBER VARIABLE DECLARATIONS

    viktar_action_t action = ACTION_NONE;  // Initialize 'action' to indicate no action is currently specified
    viktar_header_t md;  // Declare a variable 'md' of type 'viktar_header_t' for holding metadata
    viktar_footer_t footer;  // Declare a variable 'footer' of type 'viktar_footer_t' for holding footer information

    uint32_t crc32_check_data;  // Declare a variable 'crc32_check_data' of type 'uint32_t' for storing CRC32 checksum for data
    uint32_t crc32_check_header;  // Declare a variable 'crc32_check_header' of type 'uint32_t' for storing CRC32 checksum for header

    struct passwd *pwd;  // Declare a pointer 'pwd' of type 'struct passwd *' for user password information
    struct group *grp;  // Declare a pointer 'grp' of type 'struct group *' for group information
    struct tm *tm;  // Declare a pointer 'tm' of type 'struct tm *' for time information
    struct stat statbuf;  // Declare a variable 'statbuf' of type 'struct stat' for file status information

	int verbose = 0, archive_file  = STDIN_FILENO, open_file = STDOUT_FILENO, file_read = -1, file_to_write = -1, bytes_read = 0;

	char *filename = NULL;
	char buf[BUFFER_LEN] = {'\0'};

	{
		int opt = -1;

        ///START OF GETOPT
		while ((opt = getopt(argc, argv, OPTIONS)) != -1) {
			switch (opt) {
				case 'x':  // extract
					action = ACTION_EXTRACT;
					break;

				case 'c': // create a viktar archive
					action = ACTION_CREATE;
					break;

				case 't': // short table of contents
					action = ACTION_TOC_SHORT;
					break;
				case 'T': // long table of contents
					action = ACTION_TOC_LONG;
					break;

                // ONLY ONE OF THE OPTIONS ABOVE NEED TO BE CHOSEN OR WE DO NOTHING!

				case 'f': // give the file the name.
					filename = calloc(0, VIKTAR_MAX_FILE_NAME_LEN);
					strncpy(filename, optarg, VIKTAR_MAX_FILE_NAME_LEN);
					break;
				case 'V': // Validate the contents of the archive member with the CRC
					action = ACTION_VALIDATE;
					break;
				case 'h': // help
                    show_help_text_and_exit();
                    exit(EXIT_SUCCESS);
                    break;
				case 'v': // verbose
				    fprintf(stderr, "verbose level: 1\n");
				    verbose = 1;
				    break;
				default:
                    //fprintf(stderr, "oopsie - unrecognized command line option \"(null)\"\n");
                    printf("no action supplied\n");
                    printf("exiting without doing ANYTHING...");
                    exit(EXIT_FAILURE);
				    break;
			}
		}
	}

	///START OF SWITCH STATEMENT TO TAKE ON ACTION TO EXECUTE THAT WE GET FROM GETOPT!!!!!
	//Switch statement goes in the same order as getopt -x, -c, -t, -T, -f, -V

	switch (action) {
        /////////////////////////
        //CASE TO HANDLE NO OPTIONS
        /////////////////////////
		case ACTION_NONE:
			fprintf(stderr, "no action supplied\nexiting without doing ANYTHING...\n");
			if(filename != NULL) {
				free(filename);
				filename = NULL;
			}
			exit(EXIT_FAILURE);
			break;

        /////////////////////////
        /////////////////////////
        //CASE TO EXTRACT
        /////////////////////////
        /////////////////////////
        //THIS ONE WORKS
        case ACTION_EXTRACT:  // extract -X
			if (filename != NULL) {
				archive_file  = open(filename, O_RDONLY);
			}
			else{
                fprintf(stderr, "reading archive from stdin\n");
			}
			read(archive_file , buf, strlen(VIKTAR_TAG));
			if(strncmp(buf, VIKTAR_TAG, strlen(VIKTAR_TAG)) != 0) {
				fprintf(stderr, "not a viktar file: \"%s\"\n",
						filename != NULL ? filename : "stdin");
				if(filename != NULL) {
					free(filename);
					filename = NULL;
				}
				exit(EXIT_FAILURE);
			}
			if (optind < argc) {
				while((bytes_read = read(archive_file , &md, sizeof(viktar_header_t)) > 0))
				{
					int bytes_read_x = 0;
					struct timespec tmspec[2];

					crc32_check_header = crc32(0x0, Z_NULL, 0);
					crc32_check_header = crc32(crc32_check_header, (const unsigned char*)&md, sizeof(viktar_header_t));
					for (int i = optind; i < argc; i++)
					{
						if (strcmp(argv[i], md.viktar_name) == 0)
						{
							file_to_write = open(argv[i], O_WRONLY | O_CREAT | O_TRUNC);
							if(file_to_write == -1){
								fprintf(stderr, "failed to open file to extract \"%s\nexiting...\n", argv[i]);
								if(filename != NULL) {
									free(filename);
									filename = NULL;
								}
								exit(EXIT_FAILURE);
							}
							crc32_check_data = crc32(0x0, Z_NULL, 0);

							while(bytes_read_x < md.st_size)
							{
								int just_read = 0;
								if(md.st_size < (bytes_read_x + BUFFER_LEN)){
									bytes_read_x += read(archive_file , buf, just_read = md.st_size - bytes_read_x);
									crc32_check_data = crc32(crc32_check_data,(const unsigned char*)buf,just_read);
									if (verbose > 0)
										fprintf(stderr, "reached final read for %s -- size: %ld -- bytes_read: 	%d -- bytes to be read: %ld\nfinal buf: %s\n", md.viktar_name, md.st_size, bytes_read_x, md.st_size - bytes_read_x, buf);

									write(file_to_write, buf, just_read);
								}
								else{
									bytes_read_x += read(archive_file , buf, BUFFER_LEN);
									crc32_check_data = crc32(crc32_check_data, (const unsigned char*)buf, BUFFER_LEN);
									write(file_to_write, buf, BUFFER_LEN);
								}
							}
							/*
							while (bytes_read_x < md.st_size) {
                                int just_read = 0;
                                if (md.st_size < (bytes_read_x + BUFFER_LEN)) {
                                    // Read the remaining bytes if less than BUFFER_LEN is needed
                                    just_read = md.st_size - bytes_read_x;
                                } else {
                                    just_read = BUFFER_LEN;
                                }

                                // Read from archive_file into buf
                                bytes_read_x += read(archive_file, buf, just_read);

                                // Update CRC32 checksum
                                crc32_check_data = crc32(crc32_check_data, (const unsigned char*)buf, just_read);

                                // Write to file_to_write
                                if (write(file_to_write, buf, just_read) != just_read) {
                                    fprintf(stderr, "Error writing to output file\n");
                                    break;  // Exit loop on error
                                }

                                if (verbose > 0) {
                                    fprintf(stderr, "Read for %s -- size: %ld -- bytes_read: %d -- bytes to be read: %ld\n", md.viktar_name, md.st_size, bytes_read_x, md.st_size - bytes_read_x);
                                    fprintf(stderr, "buf: %.*s\n", just_read, buf);  // Print buf content as a string
                                }
                            }


							*/
							read(archive_file , &footer, sizeof(viktar_footer_t));
							if(crc32_check_data != footer.crc32_data) {
								fprintf(stderr, "*** CRC32 failure data:  %s in file: 0x%08x  extract: 0x%08x ***\n",
										argv[i], footer.crc32_data, crc32_check_data);
							}
							if(crc32_check_header != footer.crc32_header) {
								fprintf(stderr, "*** CRC32 failure header:  %s in file: 0x%08x  extract: 0x%08x ***\n",
										argv[i], footer.crc32_header, crc32_check_header);
							}
							tmspec[0] = md.st_atim;
							tmspec[1] = md.st_mtim;
							fchmod(file_to_write, md.st_mode);
							futimens(file_to_write, tmspec);
							close(file_to_write);
						}
					}
				}
			}
			//if no more commands left to process
			else {
				while((bytes_read = read(archive_file , &md, sizeof(viktar_header_t)) > 0)){
					int bytes_read_x = 0;
					struct timespec tmspec[2];

					crc32_check_header = crc32(0x0, Z_NULL, 0);
					crc32_check_header = crc32(crc32_check_header, (const unsigned char*)&md, sizeof(viktar_header_t));

					file_to_write = open(md.viktar_name, O_WRONLY | O_CREAT | O_TRUNC);
					if(file_to_write == -1){
						fprintf(stderr, "failed to open file to extract \"%s\nexiting...\n", md.viktar_name);
						if(filename != NULL) {
							free(filename);
							filename = NULL;
						}
						exit(EXIT_FAILURE);
					}
					crc32_check_data = crc32(0x0, Z_NULL, 0);

					while(bytes_read_x < md.st_size)
					{
						int just_read = 0;
						if(md.st_size < (bytes_read_x + BUFFER_LEN)){
							bytes_read_x += read(archive_file , buf, just_read = md.st_size - bytes_read_x);
							crc32_check_data = crc32(crc32_check_data, (const unsigned char*)buf, just_read);
							if (verbose > 0)
								fprintf(stderr, "reached final read for %s -- size: %ld -- bytes_read: %d -- bytes to be read: %ld\nfinal buf: %s\n", md.viktar_name, md.st_size, bytes_read_x, md.st_size - bytes_read_x, buf);
							write(file_to_write, buf, just_read);
						}
						else{
							bytes_read_x += read(archive_file , buf, BUFFER_LEN);
							crc32_check_data = crc32(crc32_check_data, (const unsigned char*)buf, BUFFER_LEN);
							write(file_to_write, buf, BUFFER_LEN);
						}
					}
					read(archive_file , &footer, sizeof(viktar_footer_t));
					if(crc32_check_data != footer.crc32_data) {
						fprintf(stderr, "*** CRC32 failure data: %s  in file: 0x%08x  extract: 0x%08x ***\n",
								md.viktar_name, footer.crc32_data, crc32_check_data);
					}
					if(crc32_check_header != footer.crc32_header) {
						fprintf(stderr, "*** CRC32 failure header: %s  in file: 0x%08x  extract: 0x%08x ***\n",
								md.viktar_name, footer.crc32_header, crc32_check_header);
					}
					tmspec[0] = md.st_atim;
					tmspec[1] = md.st_mtim;
					fchmod(file_to_write, md.st_mode);
					futimens(file_to_write, tmspec);
					close(file_to_write);
				}
			}
			if (filename != NULL) {
				open_file = close(file_read);
			}
			break;

        /*
        case ACTION_EXTRACT:  // extract -X
            if (extractOption) { // option -x
                if (fileOption) { // if -f used
                    ifd = open(FileName, O_RDONLY);
                    if (ifd < 0) {
                        fprintf(stderr, "Failed to open input archive file %s\n", FileName);
                        perror("Exiting");
                        exit(EXIT_FAILURE);
                    }
                } else { // read from stdin
                    ifd = STDIN_FILENO; // use standard input
                    strcpy(FileName, "stdin");
                    fprintf(stderr, "Reading archive from %s\n", FileName);
                }

                // Check and skip the archive tag
                buf = malloc(strlen(VIKTAR_TAG) + 1);
                if (!buf) {
                    perror("Memory allocation failed");
                    exit(EXIT_FAILURE);
                }

                bytes_read = read(ifd, buf, strlen(VIKTAR_TAG));
                if (bytes_read < 0) {
                    perror("Failed to read the file");
                    free(buf);
                    exit(EXIT_FAILURE);
                }

                buf[bytes_read] = '\0'; // Null-terminate the buffer to safely use strcmp
                if (strcmp((char *)buf, VIKTAR_TAG) != 0) {
                    fprintf(stderr, "Not a viktar file or reading tag failed: \"%s\"\n", FileName);
                    free(buf);
                    exit(EXIT_FAILURE);
                }
                free(buf);

                // Start extracting files
                while (read(ifd, &myViktarHeader, sizeof(myViktarHeader)) > 0) {
                    buf = malloc(myViktarHeader.st_size);
                    if (!buf) {
                        perror("Memory allocation failed");
                        continue;
                    }

                    // Read file content
                    bytes_read = read(ifd, buf, myViktarHeader.st_size);
                    if (bytes_read != myViktarHeader.st_size) {
                        fprintf(stderr, "Expected to read %ld bytes, read %ld\n", (long)myViktarHeader.st_size, (long)bytes_read);
                        free(buf);
                        continue;
                    }

                    // Extract the file
                    ofd = open(myViktarHeader.viktar_name, O_CREAT | O_WRONLY | O_TRUNC, myViktarHeader.st_mode);
                    if (ofd < 0) {
                        perror("Failed to open output file");
                        free(buf);
                        continue;
                    }
                    write(ofd, buf, bytes_read);
                    close(ofd);

                    // Validate CRC
                    crc32_data = crc32(0L, Z_NULL, 0);
                    crc32_data = crc32(crc32_data, buf, myViktarHeader.st_size);
                    free(buf);

                    // Read footer
                    if (read(ifd, &myViktarFooter, sizeof(myViktarFooter)) != sizeof(myViktarFooter)) {
                        fprintf(stderr, "Failed to read footer for file: %s\n", myViktarHeader.viktar_name);
                        continue;
                    }

                    if (crc32_data != myViktarFooter.crc32_data) {
                        fprintf(stderr, "*** CRC32 failure data: %s in file: 0x%08x extract: 0x%08x ***\n",
                                myViktarHeader.viktar_name, myViktarFooter.crc32_data, crc32_data);
                    }

                    // Restore metadata
                    tmbuf.actime = myViktarHeader.st_atim.tv_sec;
                    tmbuf.modtime = myViktarHeader.st_mtim.tv_sec;
                    utime(myViktarHeader.viktar_name, &tmbuf);
                    chmod(myViktarHeader.viktar_name, myViktarHeader.st_mode);
                }

                if (ifd != STDIN_FILENO) {
                    close(ifd);
                }
            }

            return EXIT_SUCCESS;
        }
        */
        /////////////////////////
        /////////////////////////
        //CASE TO CREATE
        /////////////////////////
        /////////////////////////
        case ACTION_CREATE: // create a viktar archive -c

			if (filename != NULL){
				if(verbose > 0)
					fprintf(stderr, "filename is %s\n", filename);
				open_file = open(filename, O_WRONLY | O_CREAT | O_TRUNC);
			}
			write(open_file, VIKTAR_TAG, sizeof(VIKTAR_TAG) -1 );
			//size_t tag_length = sizeof(VIKTAR_TAG) - 1;
			if (optind < argc) {
				for (int i = optind; i < argc; i++) {
					memset(&md, 0, sizeof(viktar_header_t));
					memset(&footer, 0, sizeof(viktar_footer_t));
					file_read = open(argv[i], O_RDONLY);
					memset(&statbuf, 0, sizeof(stat));

					stat(argv[i], &statbuf);
					strncpy(md.viktar_name, argv[i], VIKTAR_MAX_FILE_NAME_LEN);

					md.st_size = statbuf.st_size;
					md.st_mode = statbuf.st_mode;
					md.st_uid = statbuf.st_uid;
					md.st_gid = statbuf.st_gid;
					md.st_atim = statbuf.st_atim;
					md.st_mtim = statbuf.st_mtim;

					write(open_file, &md, sizeof(viktar_header_t));
					footer.crc32_header = crc32(footer.crc32_header, (const unsigned char*)&md, sizeof(viktar_header_t));
					memset(buf, 0, BUFFER_LEN);
					for (; ((bytes_read = read(file_read, buf, BUFFER_LEN)) > 0); ) {
						if (verbose > 0)
							fprintf(stderr, "bytes_read = %d | buf is: \n%s\n", bytes_read, buf);
						footer.crc32_data = crc32(footer.crc32_data, (const unsigned char*) buf, bytes_read );
						write(open_file, buf, bytes_read);
						memset(buf, 0, BUFFER_LEN);
					}
					write(open_file, &footer, sizeof(viktar_footer_t));
					close(file_read);
				}
			}
			if (filename != NULL) {
				open_file = close(file_read);
				chmod(filename, S_IRUSR | S_IWUSR | S_IRGRP | S_IWOTH);
				free(filename);
				filename = NULL;
			}
			break;

        /////////////////////////
        /////////////////////////
        //CASE TO OUTPUT THE SHORT TABLE
        /////////////////////////
        /////////////////////////
		case ACTION_TOC_SHORT: // short table of contents -t
			if(filename != NULL){
				fprintf(stderr, "reading archive file: \"%s\"\n",
						filename != NULL ? filename : "stdin");
				archive_file  = open(filename, O_RDONLY);
			}
			else
				fprintf(stderr, "reading archive from stdin\n");
			if(verbose > 0){
				fprintf(stderr, "archive_file  is equal to %d\n", archive_file );
			}
			read(archive_file , buf, strlen(VIKTAR_TAG));
			if(verbose > 0){
				fprintf(stderr, "buf is %s", buf);
			}
			if(strncmp(buf, VIKTAR_TAG, strlen(VIKTAR_TAG)) != 0) {
				fprintf(stderr, "not a viktar file: \"%s\"\n",
						filename != NULL ? filename : "stdin");
				if(filename != NULL) {
					free(filename);
					filename = NULL;
				}

				exit(EXIT_FAILURE);
			}

			printf("Contents of viktar file: \"%s\"\n",
					filename != NULL ? filename : "stdin");
			while (read(archive_file , &md, sizeof(viktar_header_t)) > 0) {
				memset(buf, 0, BUFFER_LEN);
				strncpy(buf, md.viktar_name, VIKTAR_MAX_FILE_NAME_LEN);
				printf("\tfile name: %s\n", buf);
				lseek(archive_file , md.st_size + sizeof(viktar_footer_t), SEEK_CUR);
			}
			if(filename != NULL) {
				close(archive_file );
				free(filename);
				filename = NULL;
			}
			break;

        /////////////////////////
        /////////////////////////
        //CASE TO OUTPUT THE LONG TABLE
        /////////////////////////
        /////////////////////////
		case ACTION_TOC_LONG:   // - T
			fprintf(stderr, "reading archive file: \"%s\"\n",
					filename != NULL ? filename : "stdin");
			if(filename != NULL){
				archive_file  = open(filename, O_RDONLY);
			}
			if(verbose > 0){
				fprintf(stderr, "archive_file  is equal to %d\n", archive_file );
			}
			read(archive_file , buf, strlen(VIKTAR_TAG));
			if(verbose > 0){
				fprintf(stderr, "buf is %s", buf);
			}
			if(strncmp(buf, VIKTAR_TAG, strlen(VIKTAR_TAG)) != 0) {
				fprintf(stderr, "not a viktar file: \"%s\"\n",
						filename != NULL ? filename : "stdin");
				if(filename != NULL) {
					free(filename);
					filename = NULL;
				}
				exit(EXIT_FAILURE);
			}

			printf("Contents of viktar file: \"%s\"\n",
					filename != NULL ? filename : "stdin");
            //this one is the correct one 6/8/2024
			while (read(archive_file , &md, sizeof(viktar_header_t)) > 0) {
				memset(buf, 0, BUFFER_LEN);
				strncpy(buf, md.viktar_name, VIKTAR_MAX_FILE_NAME_LEN);
				printf("\tfile name: %s\n", buf);
				printf("\t\tmode:         -");

				printf((md.st_mode & S_IRUSR) ? "r" : "-");
				printf((md.st_mode & S_IWUSR) ? "w" : "-");
				printf((md.st_mode & S_IXUSR) ? "x" : "-");
				printf((md.st_mode & S_IRGRP) ? "r" : "-");
				printf((md.st_mode & S_IWGRP) ? "w" : "-");
				printf((md.st_mode & S_IXGRP) ? "x" : "-");
				printf((md.st_mode & S_IROTH) ? "r" : "-");
				printf((md.st_mode & S_IWOTH) ? "w" : "-");
				printf((md.st_mode & S_IXOTH) ? "x" : "-");

				pwd = getpwuid(md.st_uid);
				grp = getgrgid(md.st_gid);

				memset(buf, 0, BUFFER_LEN);
				if (pwd == NULL){
					printf("\n\t\tuser:         UNKNOWN\n");
				}
				else {
					strcpy(buf, pwd->pw_name);
					printf("\n\t\tuser:         %s\n", buf);
				}
				memset(buf, 0, BUFFER_LEN);
				if(grp == NULL){
					printf("\t\tgroup:        UNKNOWN\n");
				}
				else {
					strcpy(buf, grp->gr_name);
					printf("\t\tgroup:        %s\n", buf);
				}
				printf("\t\tsize:         %ld\n", md.st_size);
				tm = localtime(&md.st_mtim.tv_sec);
				memset(buf, 0, BUFFER_LEN);
				strftime(buf, sizeof buf, "%Y-%m-%d %H:%M:%S %Z", tm);
				printf("\t\tmtime:        %s\n", buf);

				tm = localtime(&md.st_atim.tv_sec);
				memset(buf, 0, BUFFER_LEN);
				strftime(buf, sizeof buf, "%Y-%m-%d %H:%M:%S %Z", tm);
				printf("\t\tatime:        %s\n", buf);

				lseek(archive_file , md.st_size, SEEK_CUR);
				read(archive_file , &footer, sizeof(viktar_footer_t));

				printf("\t\tcrc32 header: 0x%08x\n", footer.crc32_header);
				printf("\t\tcrc32 data:   0x%08x\n", footer.crc32_data);

			}
            /*
            //FIX this code 6/1/2024
            while (read(archive_file, &md, sizeof(viktar_header_t)) > 0) {
                // Clear buffer before use
                memset(buf, 0, BUFFER_LEN);
                // Copy filename from md.viktar_name to buf, ensuring not to exceed VIKTAR_MAX_FILE_NAME_LEN
                strncpy(buf, md.viktar_name, VIKTAR_MAX_FILE_NAME_LEN);
                printf("\tfile name: %s\n", buf);
                printf("\t\tmode:         -");

                // Print file permissions
                printf((md.st_mode & S_IRUSR) ? "r" : "-");
                printf((md.st_mode & S_IWUSR) ? "w" : "-");
                printf((md.st_mode & S_IXUSR) ? "x" : "-");
                printf((md.st_mode & S_IRGRP) ? "r" : "-");
                printf((md.st_mode & S_IWGRP) ? "w" : "-");
                printf((md.st_mode & S_IXGRP) ? "x" : "-");
                printf((md.st_mode & S_IROTH) ? "r" : "-");
                printf((md.st_mode & S_IWOTH) ? "w" : "-");
                printf((md.st_mode & S_IXOTH) ? "x" : "-");

                // Get user and group information
                pwd = getpwuid(md.st_uid);
                grp = getgrgid(md.st_gid);

                // Clear buffer before use
                memset(buf, 0, BUFFER_LEN);
                if (pwd == NULL) {
                    printf("\n\t\tuser:         UNKNOWN\n");
                } else {
                    // Copy user name to buf
                    strcpy(buf, pwd->pw_name);
                    printf("\n\t\tuser:         %s\n", buf);
                }

                // Clear buffer before use
                memset(buf, 0, BUFFER_LEN);
                if (grp == NULL) {
                    printf("\t\tgroup:        UNKNOWN\n");
                } else {
                    // Copy group name to buf
                    strcpy(buf, grp->gr_name);
                    printf("\t\tgroup:        %s\n", buf);
                }

                // Print file size
                printf("\t\tsize:         %ld\n", md.st_size);

                // Format and print modification time (mtime)
                tm = localtime(&md.st_mtim.tv_sec);
                memset(buf, 0, BUFFER_LEN);
                strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S %Z", tm);
                printf("\t\tmtime:        %s\n", buf);

                // Format and print access time (atime)
                tm = localtime(&md.st_atim.tv_sec);
                memset(buf, 0, BUFFER_LEN);
                strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S %Z", tm);
                printf("\t\tatime:        %s\n", buf);

                // Skip to the next file in archive based on its size
                lseek(archive_file, md.st_size, SEEK_CUR);

                // Read footer information for the current file
                read(archive_file, &footer, sizeof(viktar_footer_t));

                // Print CRC32 values from footer
                printf("\t\tcrc32 header: 0x%08x\n", footer.crc32_header);
                printf("\t\tcrc32 data:   0x%08x\n", footer.crc32_data);
            }
            */
			if(filename != NULL) {
				close(archive_file );
				free(filename);
				filename = NULL;
			}
			break;
        /////////////////////////
        /////////////////////////
        //CASE TO VALIDATE
        /////////////////////////
        /////////////////////////
		case ACTION_VALIDATE:   // -V
			int count = 1;
			if (filename != NULL) {
				archive_file  = open(filename, O_RDONLY);
			}
			else
			{
				fprintf(stderr, "reading archive from stdin\n");
			}
			read(archive_file , buf, strlen(VIKTAR_TAG));
			if(strncmp(buf, VIKTAR_TAG, strlen(VIKTAR_TAG)) != 0) {
				fprintf(stderr, "not a viktar file: \"%s\"\n",
						filename != NULL ? filename : "stdin");
				if(filename != NULL) {
					close(archive_file );
					free(filename);

					filename = NULL;
				}
				/*
                if (filename != NULL) {
                    close(archive_file); // Incorrectly close archive_file without checking if it's a valid descriptor
                    free(filename);
                    filename = NULL;
                }
				*/
				exit(EXIT_FAILURE);
			}
			while((bytes_read = read(archive_file , &md, sizeof(viktar_header_t)) > 0)){
				int bytes_read_x = 0;
				bool pass_data = FALSE;
				bool pass_header = FALSE;

				crc32_check_header = crc32(0x0, Z_NULL, 0);
				crc32_check_header = crc32(crc32_check_header, (const unsigned char*)&md, sizeof(viktar_header_t));
				crc32_check_data = crc32(0x0, Z_NULL, 0);

                /*
                while (bytes_read_x < md.st_size) {
                    int just_read = 0;

                    if (md.st_size < (bytes_read_x + BUFFER_LEN)) {
                        // Calculate bytes left to read
                        just_read = md.st_size - bytes_read_x;
                    } else {
                        just_read = BUFFER_LEN;
                    }
                */
				while(bytes_read_x < md.st_size)
				{
					int just_read = 0;
					if(md.st_size < (bytes_read_x + BUFFER_LEN)){
						bytes_read_x += read(archive_file , buf, just_read = md.st_size - bytes_read_x);
						crc32_check_data = crc32(crc32_check_data, (const unsigned char*)buf, just_read);
						if (verbose > 0)
							fprintf(stderr, "reached final read for %s -- size: %ld -- bytes_read: %d -- bytes to be read: %ld\nfinal buf: %s\n", md.viktar_name, md.st_size, bytes_read_x, md.st_size - bytes_read_x, buf);
						write(file_to_write, buf, just_read);
					}
					else{
						bytes_read_x += read(archive_file , buf, BUFFER_LEN);
						crc32_check_data = crc32(crc32_check_data, (const unsigned char*)buf, BUFFER_LEN);
						write(file_to_write, buf, BUFFER_LEN);
					}
				}
				read(archive_file , &footer, sizeof(viktar_footer_t));
				printf("Validation for data member %d:\n", count);
				fflush(stdout);

				if(crc32_check_header != footer.crc32_header) {
					printf("\tHeader crc does not match: 0x%08x   0x%08x for member %d\n",
							crc32_check_header, footer.crc32_header, count);
				}
				else {
					printf("\tHeader crc does match:     0x%08x   0x%08x for member %s\n",
							crc32_check_header, footer.crc32_header, md.viktar_name);
					pass_header = TRUE;
				}
				fflush(stdout);
				if(crc32_check_data != footer.crc32_data) {
					printf("\tData crc does not match:   0x%08x   0x%08x for member %d\n",
							crc32_check_data, footer.crc32_data,count );
				}
				else{
					printf("\tData crc does match:       0x%08x   0x%08x for member %s\n",
							crc32_check_data, footer.crc32_data, md.viktar_name);
					pass_data = TRUE;
				}
				fflush(stdout);
				if (pass_data == TRUE && pass_header == TRUE) {
					printf("\tValidation success:        %s for member %d\n", filename != NULL ? filename : "stdin", count);
				}
				count += 1;
			}
			close(file_to_write);
			break;
	}

	if(filename != NULL) {
		free(filename);     // Deallocate the memory that 'filename' points to
		filename = NULL;    // Set 'filename' to NULL to avoid a dangling pointer
	}
	return EXIT_SUCCESS;    // Return a success status from the function
}

/////////////////////////
/////////////////////////
// Function definition for show_help_text_and_exit function
/////////////////////////
/////////////////////////
void show_help_text_and_exit(void) //print the help function -h
{
	printf("help text\n");
    printf("\t./viktar\n");
	printf("\tOptions: xctTf:Vhv\n");
	printf("\t\t-x\t\textract file/files from archive\n");
	printf("\t\t-c\t\tcreate an archive file\n");
	printf("\t\t-t\t\tdisplay a short table of contents of the archive file\n");
	printf("\t\t-T\t\tdisplay a long table of contents of the archive file\n");
	printf("\t\tOnly one of xctTV can be specified\n");
	printf("\t\t-f filename\tuse filename as the archive file\n");
    printf("\t\tV\t\tvalidate the crc values in the viktar file\n");
	printf("\t\t-v\t\tgive verbose diagnostic messages\n");
	printf("\t\t-h\t\tdisplay this AMAZING help message\n");

    // Exit the program with a success status
    exit(EXIT_SUCCESS);
}

