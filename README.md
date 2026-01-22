# NOX - System Abstraction Language

Chào mừng bạn đến với source code của **NOX**. Đây là một dự án Monorepo quy mô lớn, được thiết kế để xây dựng một nền tảng visual programming/collaboration.

##  Tech Stack

Dự án sử dụng các công nghệ hiện đại nhất (Enterprise Grade):

*   **Monorepo Manager:** [TurboRepo](https://turbo.build/) (High-performance build system)
*   **Package Manager:** [pnpm](https://pnpm.io/) (Fast, efficient)
*   **Backend:** [NestJS](https://nestjs.com/) (Modular, TypeScript framework)
*   **Frontend:** [React](https://react.dev/) + [Vite](https://vitejs.dev/) + [Tailwind CSS](https://tailwindcss.com/)
*   **Database:** PostgreSQL + [Prisma ORM](https://www.prisma.io/)
*   **Infrastructure:** Docker & Docker Compose

## 🛡️ Giấy Phép & Chiến Lược Mã Nguồn (Open Core)

NOX tuân theo mô hình **Open Core**:
*   **Community Edition (Công Khai):** Miễn phí vĩnh viễn. Bao gồm hạ tầng cốt lõi, xác thực (auth), và dashboard cơ bản.
*   **Enterprise Edition (Riêng Tư):** Chứa các tính năng nâng cao độc quyền.

**Các Tính Năng Hạn Chế (Chỉ Enterprise):**
1.  **Block Ecosystem & Relations Logic:** Các thuật toán phức tạp xử lý tương tác giữa các block và luồng dữ liệu.
2.  **Advanced Invader System:** Logic độc quyền để tích hợp bên ngoài và các tác vụ tự động (Invaders).

> Mã nguồn của các tính năng này nằm trong `packages/nox-enterprise` (không bao gồm trong kho lưu trữ công khai này).

---

##  Quick Start (Cho Dev Mới)

### 1. Prerequisites
Đảm bảo máy bạn đã cài:
*   Node.js (>= 18)
*   pnpm (`npm install -g pnpm`)
*   Docker & Docker Desktop

### 2. Installation
Chạy lệnh sau tại root folder để cài dependency cho TẤT CẢ apps/packages:

```bash
pnpm install
```

### 3. Environment Setup
Hệ thống cần các file `.env` để chạy. Copy các file mẫu (hoặc tạo mới):

**`apps/api/.env`**
```env
DATABASE_URL="postgresql://nox_user:nox_password@localhost:5432/nox_db?schema=public"
JWT_SECRET="super-secret-jwt-key-nox-2024" # Thay đổi khi lên production
PORT=3000
```

**`apps/web/.env`**
```env
VITE_API_URL="http://localhost:3000/api/v1"
```

**`packages/database/.env`**
```env
DATABASE_URL="postgresql://nox_user:nox_password@localhost:5432/nox_db?schema=public"
```

### 4. Start Infrastructure (Database)
Chạy PostgreSQL, Redis, MinIO qua Docker:

```bash
cd docker
docker-compose up -d
```

### 5. Sync Database Schema
Đẩy cấu trúc db từ prisma xuống postgres:

```bash
pnpm --filter @nox/database db:push
```

### 6. Run Development Server
Quay lại root folder và chạy:

```bash
# Windows
.\dev.bat

# Mac/Linux
pnpm dev
```

*   **API:** http://localhost:3000
*   **Frontend:** http://localhost:3003 (hoặc port hiển thị trên terminal)

---

##  Project Structure

Chúng ta tuân thủ cấu trúc **Separation of Concerns**:

```
NOX/
├── apps/               # Các ứng dụng chính
│   ├── api/            # Backend (NestJS) - Xử lý logic, Auth, API
│   └── web/            # Frontend (React) - Giao diện người dùng
├── packages/           # Shared Code (Dùng chung cho cả API và Web)
│   ├── database/       # Prisma Schema & Client (Single Source of Truth)
│   ├── tsconfig/       # Cấu hình TypeScript chung
│   └── eslint-config/  # Cấu hình Linter chung
├── docker/             # Cấu hình Docker services
└── .shared/            # Design System Data & AI Assets
```

###  Database Workflow (Quan trọng)

Database schema nằm tại: `packages/database/prisma/schema.prisma`.

Mỗi khi bạn cần sửa Database (thêm bảng, thêm cột):
1.  Sửa file `.prisma` trên.
2.  Chạy lệnh: `pnpm --filter @nox/database db:push`
3.  Prisma sẽ tự động sinh lại TypeScript types cho cả Backend và Frontend.

---

##  Contribution Guidelines

*   **Commit Message:** Tuân thủ Conventional Commits (Husky sẽ chặn nếu sai format).
    *   `feat: add new block type`
    *   `fix: resolve login error`
    *   `refactor: cleanup auth service`
*   **Linting:** Code được tự động format bởi Prettier và check bởi ESLint trước khi commit.

---

## 🗺 Roadmap

*   [x] Basic Authentication (JWT, Guards)
*   [x] Database Schema Foundation
*   [x] Monorepo Setup (Webpack, Turbo)
*   [ ] Block Logic Implementation (Canvas Editor)
*   [ ] Plugin System

---

##  Recommended Tech Stack & Strategy (Định Hướng Công Nghệ)

Để đảm bảo hệ thống scale tốt và tránh nợ kỹ thuật (Technical Debt), dưới đây là các công nghệ được **khuyến nghị** cho các features tiếp theo:

### 1. Visual Editor / Canvas Engine
*   **Recommendation:** [React Flow](https://reactflow.dev/) (hoặc `@xyflow/react`)
*   **Lý do:**
    *   Tối ưu tuyệt đối cho Node-based editor (phù hợp với mô hình Blocks & Relations của NOX).
    *   Tích hợp mượt mà với React & Tailwind CSS.
    *   Hỗ trợ sẵn Minimap, Controls, Background, và Custom Nodes.
    *   *Alternative:* `Konva` (Nếu cần vẽ tự do kiểu Photoshop/Figma), nhưng với System Design thì React Flow là số 1.

### 2. Real-time Collaboration (Multiplayer)
*   **Recommendation:** [Socket.io](https://socket.io/) (via NestJS Gateways) kết hợp [Yjs](https://yjs.dev/)
*   **Lý do:**
    *   **Socket.io:** NestJS hỗ trợ native module cho Socket.io, cực kỳ dễ implement Auth Guard.
    *   **Yjs:** Là thư viện chuẩn công nghiệp cho CRDT (Conflict-free Replicated Data Types). Giúp xử lý việc 2 người cùng kéo 1 block mà không bị conflict dữ liệu.

### 3. Background Job Processing (Queue)
*   **Recommendation:** [BullMQ](https://docs.bullmq.io/) (trên Redis)
*   **Lý do:**
    *   Khi user bấm "Generate Code" hoặc "Export Project", task này có thể mất 10-30s. Không được để API chờ.
    *   BullMQ giúp đẩy task vào hàng đợi, xử lý ngầm, và có cơ chế Retry khi lỗi.
    *   Đã có sẵn Redis trong Docker Compose rồi, tận dụng luôn.

### 4. Advanced State Management (Frontend)
*   **Recommendation:** [Zustand](https://docs.pmnd.rs/zustand) + [Immer](https://immerjs.github.io/immer/)
*   **Lý do:**
    *   Hệ thống Block lồng nhau (Nested Blocks) rất phức tạp.
    *   `Immer` giúp update state nested dễ dàng (`state.blocks[id].position.x = 100`) mà không cần spread operator loằng ngoằng.
    *   Tiếp tục dùng Zustand để đồng bộ với Auth Store hiện tại.

---
*Happy Coding!* 
