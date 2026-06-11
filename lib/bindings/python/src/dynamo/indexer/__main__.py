# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import os

os.environ["DYNAMO_SKIP_PYTHON_LOG_INIT"] = "1"

from dynamo.indexer.main import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
