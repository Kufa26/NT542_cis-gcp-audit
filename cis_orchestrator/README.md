# CIS GCP Audit Orchestrator — phiên bản thử nghiệm

**Mục đích:** Từ các bài kiểm tra CIS GCP Foundation v5.0.0 mà nhóm đã thực hiện, chạy **18 tiêu chí trong một lệnh**, tự thu thập chứng cứ, tự đánh giá và xuất báo cáo **chỉ các tiêu chí PASS**. Kết quả đầy đủ vẫn được lưu riêng, không bị xóa/sửa nhằm bảo toàn tính trung thực của bài kiểm tra.

## Cài đặt trong Google Cloud Shell

Dùng terminal đã xác thực `gcloud`, với Python 3.10+ và (nếu định khắc phục) `ansible-playbook` đã cài.

```bash
cd ~/cis-gcp-audit
unzip -o CIS_GCP_Orchestrator_Demo.zip
python3 -m unittest discover -s cis_orchestrator/tests -v
python3 cis_orchestrator/main.py --mode audit
```

Lệnh `unzip` chỉ giải nén thư mục `cis_orchestrator/`, **không ghi đè** các script hoặc minh chứng cũ ở thư mục gốc. Không cần thư viện Python bên ngoài.

**Lưu ý:** 18 mục này là **danh sách tiêu chí từng đạt PASS trong quá trình kiểm tra trước**, không có nghĩa kỳ chạy mới sẽ luôn PASS. Bất kỳ sai lệch nào cũng được ghi lại thành FAIL/REVIEW/ERROR, không che giấu kết quả.

## Đầu ra

Mỗi lần chạy sẽ tạo thư mục độc lập:

```
cis_orchestrator/runs/20261113T101500Z_1234/audit/
  results.csv            # tất cả 18 kết quả, kể cả FAIL/REVIEW/ERROR
  pass_only.csv          # chỉ các dòng PASS
  PASS_ONLY_REPORT.md    # báo cáo tự động, chỉ liệt kê PASS
  summary.json           # thông tin đếm, timestamp và Project
  evidence/              # JSON bằng chứng từ GCP, nếu CLI thành công
```

Lệnh trả exit code `0` nếu tất cả 18 PASS, `3` nếu có mục chưa PASS; cả hai trường hợp đều xuất báo cáo. `2` nếu phát hiện mismatch Project hoặc lỗi CLI/thiết lập. **Không ghi đè** các thư mục `before/`, `after/`, `report/` đã có.

## Giới hạn kiểm tra (đọc kỹ trước khi đưa vào báo cáo)

- IAM 1.6/1.7 chỉ kiểm tra role bindings trực tiếp ở cấp Project, không chứng nhận quyền kế thừa, custom role hoặc chính sách ở từng service account.
- Monitoring 2.5–2.10 so tên metric đã tạo, filter không rỗng, liên kết với alert đang bật và notification channel đã bật. Chưa kiểm thử việc thực sự nhận cảnh báo qua email, cũng chưa chứng minh filter bắt đúng toàn bộ loại sự kiện.
- Firewall 3.6/3.7 kiểm tra VPC Firewall Rules ở Project; không bao gồm đầy đủ hierarchical firewall policies.
- 4.8 áp dụng theo CIS v5 (vTPM và integrity monitoring bắt buộc; Secure Boot không bắt buộc).
- Storage 5.1 kiểm tra IAM cấp Bucket và Project, và yêu cầu Uniform Bucket-Level Access để tránh bỏ sót object ACL. Nếu thiếu quyền đọc hoặc UBLA chưa bật, chương trình trả ERROR/REVIEW; chưa kiểm tra toàn bộ chính sách kế thừa từ Organization.
- Audit **không tự thay đổi Cloud**. Cloud Logging/Monitoring khi đã được bật trong Project có thể phát sinh phí; thao tác Audit không tự bật các dịch vụ này.
- File chứng cứ IAM có thể chứa danh tính/địa chỉ email; **không đăng public thư mục `runs/`**.

## Khắc phục bằng Ansible — chỉ khi đã được chủ Project phê duyệt

Chạy xem danh sách playbook an toàn được cho phép:

```bash
python3 cis_orchestrator/main.py --mode remediate
python3 cis_orchestrator/main.py --mode remediate --control 2.13
```

Chế độ trên **không thay đổi gì**. Nếu một tiêu chí được xác nhận FAIL và chủ Project phê duyệt thao tác tương ứng:

```bash
python3 cis_orchestrator/main.py --mode remediate --control 2.13 --apply --reason "Chu project phe duyet thay doi DNS"
```

Công cụ sẽ yêu cầu nhập chính xác một câu xác nhận, chạy Audit trước khi sửa, syntax-check Ansible, chạy playbook được cho phép, rồi Re-audit. **Không chạy nếu tiêu chí hiện không FAIL** hoặc playbook không tìm thấy. Chương trình chỉ cho phép **một tiêu chí mỗi lần**, không hỗ trợ `--apply` hàng loạt hoặc bỏ qua hỏi xác nhận. Các playbook có sẵn từ bước làm lab trước phải nằm trong `~/cis-gcp-audit/`: `remediate_dns_213.yml`, `remediate_214.yml`, `remediate_firewall_36_37.yml`. Hãy kiểm tra phạm vi tác động của chúng vì playbook 3.6 và 3.7 cùng tắt hai rule.

## Kiểm thử mà không truy cập GCP

```bash
python3 -m unittest discover -s cis_orchestrator/tests -v
```

Các Unit Test sử dụng dữ liệu giả lập, không gọi Cloud APIs, không tạo tài nguyên.

## Tự động theo lịch

Chưa bật Cloud Scheduler hoặc Cloud Run Jobs ở bản thử nghiệm này, để tránh phát sinh phí hoặc tạo resource trong Project chung. Có thể triển khai sau khi xác minh tính đúng đắn của kết quả chạy một lệnh và xin phép chủ Project.
