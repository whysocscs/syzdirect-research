#!/usr/bin/env python3
"""v6.3 커널 kcov.c에 SyzDirect 패치 적용"""
import sys

path = sys.argv[1]
src = open(path).read()

# 1. DISTBLOCKSIZE 정의
src = src.replace(
    '#include <linux/vmalloc.h>',
    '#include <linux/vmalloc.h>\n#define DISTBLOCKSIZE 300'
)

# 2. __sanitizer_cov_trace_pc 시그니처 + dt_area 변수 추가
src = src.replace(
    'void notrace __sanitizer_cov_trace_pc(void)\n{',
    'void notrace __sanitizer_cov_trace_pc(u32 dt)\n{\n\tu32* dt_area;'
)

# 3. area 포인터 분리 (첫 번째 occurrence만 - __sanitizer_cov_trace_pc 내)
src = src.replace(
    '\tarea = t->kcov_area;',
    '\tdt_area = t->kcov_area;\n\tarea = (unsigned long*)((u32*)t->kcov_area + DISTBLOCKSIZE);',
    1  # 첫 번째 occurrence만 교체
)


# 4. 사이즈 체크 수정
src = src.replace(
    'if (likely(pos < t->kcov_size)) {',
    'if (likely(pos < t->kcov_size - DISTBLOCKSIZE / 2)) {'
)

# 5. barrier() 제거 + dt update 추가
src = src.replace(
    '\t\tWRITE_ONCE(area[0], pos);\n\t\tbarrier();\n\t\tWRITE_ONCE(area[pos], _RET_IP_);\n\t}',
    '\t\tWRITE_ONCE(area[0], pos);\n\t\tWRITE_ONCE(area[pos], _RET_IP_);\n\t}\n\tif (dt < READ_ONCE(dt_area[0]))\n\t\tWRITE_ONCE(dt_area[0], dt);'
)

# 6. kcov_mark_block 함수 추가
mark_block = '''
void notrace kcov_mark_block(u32 i)
{
\tstruct task_struct *t;
\tu32 *dt_area;
\tt = current;
\tif (!check_kcov_mode(KCOV_MODE_TRACE_PC, t))
\t\treturn;
\tdt_area = (u32*)t->kcov_area + 1;
\tWRITE_ONCE(dt_area[i], READ_ONCE(dt_area[i]) + 1);
}
EXPORT_SYMBOL(kcov_mark_block);
'''
export_pos = src.find('EXPORT_SYMBOL(__sanitizer_cov_trace_pc)')
if export_pos != -1:
    src = src[:export_pos] + mark_block + src[export_pos:]

open(path, 'w').write(src)
print(f"[patch_kcov_v63] {path} 패치 완료")
