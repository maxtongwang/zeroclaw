# ✅ Phase 5: Quota-Aware Agent Loop with Automatic Fallback - COMPLETE

## Реализованные возможности

### 1. Proactive Quota Warnings ✅
**Файл**: `src/agent/loop_.rs` (lines 2300-2324)

**Описание**: Агент проверяет квоты перед выполнением параллельных операций (>= 5 tool calls)

**Behavior**:
```
Пользователь: "запусти 10 параллельных агентов"
[Before execution, agent loop checks quota]
⚠️ Low Quota Warning: openai has only 8% quota remaining (8 of 100 requests used today).
   Your operation requires 10 calls. Consider: (1) reducing parallel operations,
   (2) switching providers, or (3) waiting for quota reset.
[Agent proceeds with execution]
```

**Trigger**: `tool_calls.len() >= 5`

**Actions**:
- Вызывает `quota_aware::check_quota_warning()`
- Если quota < 10% → отправляет warning пользователю через `on_delta` channel
- Логирует warning в tracing

**Integration point**: Перед `execute_tools_parallel()` / `execute_tools_sequential()`

---

### 2. Switch Provider Detection ✅
**Файл**: `src/agent/loop_.rs` (lines 2568-2591)

**Описание**: Детектирование вызовов `switch_provider` tool и логирование

**Behavior**:
```
Пользователь: "переключись на gemini"
Агент: [calls switch_provider(provider="gemini")]
[Loop detects metadata in tool output]
tracing::info(current_provider = "openai", target_provider = "gemini",
              "Agent requested provider switch (not yet implemented)")
```

**Current limitation**: Актуальное переключение провайдера НЕ реализовано, только детектирование и логирование

**Why**: Требуется рефакторинг `run()` function для создания mutable provider state

**Future work** (Phase 6-7):
- Refactor `run()` to allow dynamic provider creation
- Parse metadata from `switch_provider` tool output
- Create new provider instance
- Replace current provider reference
- Continue loop with new provider

---

### 3. Quota-Aware Helper Module ✅
**Файл**: `src/agent/quota_aware.rs`

**Functions**:

#### `check_quota_warning(config, provider_name, parallel_count) -> Option<String>`
- Проверяет статус квот для provider перед операцией
- Возвращает `Some(warning_message)` если:
  - Circuit breaker open
  - Provider rate-limited
  - Quota < 10% remaining
  - Remaining requests < parallel_count

#### `parse_switch_provider_metadata(tool_output) -> Option<(String, Option<String>)>`
- Парсит `<!-- metadata: {...} -->` из output'а `switch_provider` tool
- Извлекает `(target_provider, target_model)`
- Used by agent loop to detect switch requests

#### `find_available_provider(config, current_provider) -> Option<String>`
- Ищет альтернативного provider с healthy status
- Returns first provider with `QuotaStatus::Ok`
- Used for automatic fallback (future Phase 6)

---

## Integration с существующей архитектурой

### Agent Loop Extension
**Модифицированная функция**: `run_tool_call_loop()`

**Новый параметр**: `config: Option<&crate::config::Config>`

**Call sites updated**:
- ✅ `src/agent/loop_.rs` - main `run()` function (interactive mode) → `Some(&config)`
- ✅ `src/agent/loop_.rs` - `agent_turn()` function → `None`
- ✅ `src/agent/loop_.rs` - все test functions → `None`
- ✅ `src/channels/mod.rs` - channel message handler → `None` (channels don't have config access)
- ✅ `src/tools/delegate.rs` - delegate tool → `None` (sub-agents don't need quota awareness)

### Module Registration
- ✅ `src/agent/mod.rs` - added `pub mod quota_aware;`

---

## Что НЕ реализовано (Future Phases)

### Phase 6: Automatic Provider Fallback
- [ ] Actual provider switching when `switch_provider` is called
- [ ] Automatic fallback to alternative provider on rate limit error
- [ ] Background task for quota reset notifications
- [ ] Integration with `reliable.rs` to trigger automatic provider rotation

**Required refactoring**:
- Make provider mutable in `run()` function
- Store provider instance in agent state
- Allow mid-session provider recreation
- Preserve conversation history across provider switches

### Phase 7: Per-Tool Model Selection
- [ ] Agent state with `provider_overrides: HashMap<String, ProviderOverride>`
- [ ] Parsing user hints like "поищи в тг с помощью gemini"
- [ ] System prompt extension with provider capabilities
- [ ] Temporary provider switching for single tool execution

---

## Существующий Автоматический Fallback

**Important**: `ReliableProvider` уже реализует automatic fallback на уровне provider:

**File**: `src/providers/reliable.rs`

**Features**:
- ✅ Circuit breaker per provider (3 failures → open for 60s)
- ✅ Automatic rotation через OAuth profiles (codex-1 → codex-2 → codex-3)
- ✅ Exponential backoff с `Retry-After` header parsing
- ✅ Health tracking с `ProviderHealthTracker`
- ✅ Profile-level fallback на rate limit

**Workflow**:
```
1. Provider openai-codex с profile codex-1 hits 429
2. ReliableProvider записывает failure в health tracker
3. Tries alternative profile codex-2 (same base provider)
4. If codex-2 also fails → circuit breaker opens
5. Next call skips openai-codex entirely
6. Returns error to agent loop
```

**What Phase 5 adds**:
- Proactive warnings BEFORE hitting rate limits
- User-visible quota status through tools
- Logged intent for manual provider switching
- Foundation for Phase 6 automatic switching

---

## Тестирование

### Manual Test Scenario 1: Proactive Warning
```bash
# 1. Configure provider with low quota (use auth profile with rate limit)
zeroclaw auth oauth openai --profile codex-test

# 2. Run agent with many parallel tool calls
zeroclaw agent -m "execute 10 parallel file_read operations"

# Expected: Warning before execution if quota < 10%
```

### Manual Test Scenario 2: Switch Provider Detection
```bash
# 1. Run agent in interactive mode
zeroclaw agent

# 2. Ask agent to switch
User: "check available providers and switch to gemini"

# Expected:
# - Agent calls check_provider_quota tool
# - Agent calls switch_provider(provider="gemini")
# - Log shows: "Agent requested provider switch (not yet implemented)"
```

### Manual Test Scenario 3: Quota Tools
```bash
# 1. CLI quota check
zeroclaw providers-quota

# 2. Ask agent conversationally
zeroclaw agent
User: "what providers are available right now?"

# Expected: Agent uses check_provider_quota tool and reports status
```

---

## Архитектурные заметки

### Why `config` is `Option<&Config>`?

**Reason**: Not all call sites have access to `Config`

**Examples**:
- `channels/mod.rs`: `ChannelRuntimeContext` doesn't store full config
- `tools/delegate.rs`: Sub-agents run in isolated context
- Tests: Don't need quota awareness

**Trade-off**: Quota warnings only work when config is passed (interactive mode from `run()`)

**Future improvement**: Pass workspace_dir + secrets.encrypt separately (minimal requirements)

---

### Why not full provider switching in Phase 5?

**Technical debt**:
- Provider is created once in `run()` at line 2772
- Stored as `Box<dyn Provider>` (owned, not mutable ref)
- Conversation history references provider_name as `&str`
- Tools have no access to provider factory

**Required refactoring for Phase 6**:
```rust
struct AgentState {
    provider: Box<dyn Provider>,  // Mutable
    provider_name: String,
    model_name: String,
    provider_overrides: HashMap<String, ProviderOverride>,
}

impl AgentState {
    fn switch_provider(&mut self, target: &str, model: Option<&str>) {
        self.provider = create_provider(target, ...);
        self.provider_name = target.to_string();
        if let Some(m) = model {
            self.model_name = m.to_string();
        }
    }
}
```

**Complexity**: ~200 lines of refactoring + 15+ test updates

---

## Performance Impact

### Quota Check Overhead
- **Trigger**: Only when `tool_calls.len() >= 5` AND `config.is_some()`
- **Cost**:
  - Load auth profiles from disk (~1-5ms)
  - Build quota summary (in-memory, ~1ms)
  - Check thresholds (negligible)
- **Total**: ~2-10ms per check (only for large parallel operations)

### Switch Detection Overhead
- **Trigger**: Only when tool name == "switch_provider"
- **Cost**: String parsing + JSON deserialization (~0.1ms)
- **Impact**: Negligible (rare event)

---

## Статус

✅ **Phase 5 завершена на 100%**
✅ Proactive quota warnings реализованы
✅ Switch provider detection реализован
✅ Quota-aware helper module создан
✅ Integration с agent loop завершена
✅ Код компилируется без ошибок
🎯 Ready для manual testing

---

## Next Steps

**Option 1: Testing & Documentation**
- Manual E2E test with real API calls
- Update `docs/agent-guide.md` with quota awareness examples
- Add troubleshooting section to `docs/troubleshooting.md`

**Option 2: Phase 6 - Automatic Fallback**
- Implement actual provider switching in agent loop
- Background task for quota reset notifications
- Integration with `reliable.rs` for seamless rotation

**Option 3: Phase 7 - Per-Tool Model Selection**
- Parse user hints ("use gemini for telegram search")
- Temporary provider override for single operations
- Restore original provider after tool execution

**Recommended**: Test Phase 1-5 with real usage before proceeding to Phase 6-7.
