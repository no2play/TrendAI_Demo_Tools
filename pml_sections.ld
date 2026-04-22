/* pml_sections.ld
 * Forces .payload section to be marked executable + readable in the PE.
 * High-entropy + executable = shellcode staging signal for ATSE.
 */
SECTIONS
{
  .payload : { *(.payload) } :text
}
INSERT AFTER .text;
