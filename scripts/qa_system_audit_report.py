from pathlib import Path
import json
import re
import pdfplumber
from PIL import Image, ImageDraw

ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'output/pdf'
QA=ROOT/'tmp/pdfs/system-audit-final'

def main():
    aux=(OUT/'ahr-idps-system-audit.aux').read_text(encoding='utf-8')
    labels={key:int(page) for key,page in re.findall(r'\\newlabel\{(node\d+(?:start|second|end))\}\{\{[^}]*\}\{(\d+)\}',aux)}
    nodes=[]
    for i in range(1,30):
        start=labels[f'node{i}start']; second=labels[f'node{i}second']; end=labels[f'node{i}end']
        nodes.append(dict(node=f'N{i:02}',start_page=start,second_page=second,end_page=end,two_pages=(second==start+1 and end==second)))
    assert all(n['two_pages'] for n in nodes), nodes
    issues=[]
    with pdfplumber.open(OUT/'ahr-idps-system-audit.pdf') as pdf:
        page_count=len(pdf.pages)
        for i,page in enumerate(pdf.pages,1):
            text=page.extract_text() or ''
            if len(text.strip())<40: issues.append(dict(page=i,problem='almost_blank'))
            if '\ufffd' in text: issues.append(dict(page=i,problem='replacement_character'))
            for char in page.chars:
                if char['x0']<28 or char['x1']>page.width-28 or char['top']<15 or char['bottom']>page.height-15:
                    issues.append(dict(page=i,problem='outside_safe_page',text=char['text']))
                    break
    images=sorted(QA.glob('page-*.png'))
    sheets=[]
    for start in range(0,len(images),6):
        sheet=Image.new('RGB',(1240,2640),'#e4e4e4'); draw=ImageDraw.Draw(sheet)
        for local,path in enumerate(images[start:start+6]):
            im=Image.open(path).convert('RGB'); im.thumbnail((600,840))
            x=20+(local%2)*620; y=28+(local//2)*880
            sheet.paste(im,(x,y)); draw.text((x,y-17),path.stem,fill='black')
        target=QA/f'contact-{start//6+1:02}.png'; sheet.save(target); sheets.append(str(target))
    report=dict(pdf_pages=page_count,nodes=nodes,pagination_pass=all(n['two_pages'] for n in nodes),
                text_geometry_issues=issues,rendered_pages=len(images),contact_sheets=sheets)
    (OUT/'ahr-idps-report-qa.json').write_text(json.dumps(report,indent=2,ensure_ascii=False),encoding='utf-8')
    print(json.dumps(dict(pdf_pages=page_count,node_count=len(nodes),pagination_pass=report['pagination_pass'],
                         text_geometry_issues=issues,rendered_pages=len(images),contact_sheets=len(sheets)),indent=2))

if __name__=='__main__': main()
